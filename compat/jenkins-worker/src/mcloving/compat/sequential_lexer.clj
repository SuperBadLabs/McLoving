(ns mcloving.compat.sequential-lexer
  "Bounded source recognizer. No Groovy evaluation or runtime operations."
  (:require [clojure.string :as str])
  (:import (java.nio ByteBuffer)
           (java.nio.charset StandardCharsets CodingErrorAction)))

(defn fail! [code] (throw (ex-info "sequential source outside contract" {:code code})))
(defn byte-count [s] (alength (.getBytes ^String s StandardCharsets/UTF_8)))
(defn source-text! [^bytes bytes]
  (when (> (alength bytes) 16384) (fail! "E_SOURCE_TOO_LARGE"))
  (let [s (try (str (.decode (doto (.newDecoder StandardCharsets/UTF_8)
                              (.onMalformedInput CodingErrorAction/REPORT)
                              (.onUnmappableCharacter CodingErrorAction/REPORT))
                            (ByteBuffer/wrap bytes)))
               (catch java.nio.charset.CharacterCodingException _ (fail! "E_SOURCE_TEXT")))]
    (when (or (str/starts-with? s "\ufeff") (str/includes? s "\r") (str/includes? s "\u0000"))
      (fail! "E_SOURCE_TEXT"))
    s))

(defn stage-id [name]
  (let [folded (apply str (map #(if (<= (int \A) (int %) (int \Z))
                                 (char (+ 32 (int %))) %) name))
        id (-> folded (str/replace #"[^a-z0-9._-]+" "-") (str/replace #"^-+|-+$" ""))]
    (when (or (empty? id) (> (count id) 96) (> (byte-count name) 96)) (fail! "E_STAGE_NAME"))
    id))

(def escapes {\\ \\ \' \' \" \" \$ \$ \n \newline \r \return \t \tab \b \backspace \f \formfeed})
(defn tokens [^String source]
  ;; Groovy consumes Unicode escapes before comments; inspect original runs.
  (doseq [[_ run] (re-seq #"(\\+)u" source)]
    (when (odd? (count run)) (fail! "E_SOURCE_LEXICAL")))
  (let [n (count source)
        at (fn [i] (when (< i n) (.charAt source i)))
        starts (fn [i s] (.startsWith source ^String s i))]
    (loop [i 0 out []]
      (if (>= i n) (conj out {:kind :eof})
        (let [c (at i)]
          (cond
            (#{\space \tab \formfeed} c) (recur (inc i) out)
            (= c \newline) (recur (inc i) (conj out {:kind :lf}))
            (or (and (zero? i) (starts i "#!")) (starts i "//"))
            (recur (or (str/index-of source "\n" i) n) out)
            (starts i "/*")
            (if-let [end (str/index-of source "*/" (+ i 2))]
              (recur (+ end 2) out) (fail! "E_SOURCE_PARSE"))
            (#{\{ \} \( \) \;} c) (recur (inc i) (conj out {:kind c}))
            (or (= c \') (= c \"))
            (let [triple (starts i (apply str (repeat 3 c)))
                  delim (apply str (repeat (if triple 3 1) c))
                  [next-i value dynamic]
                  (loop [j (+ i (count delim)) value (StringBuilder.) dynamic false]
                    (cond
                      (>= j n) (fail! "E_SOURCE_PARSE")
                      (starts j delim) [(+ j (count delim)) (str value) dynamic]
                      (= (at j) \\)
                      (let [e (at (inc j))]
                        (when-not (contains? escapes e) (fail! "E_SOURCE_LEXICAL"))
                        (.append value ^char (get escapes e))
                        (recur (+ j 2) value dynamic))
                      (and (not triple) (= (at j) \newline)) (fail! "E_SOURCE_PARSE")
                      :else (do (.append value ^char (at j))
                                (recur (inc j) value (or dynamic (and (= c \") (= (at j) \$)))))))]
              (recur next-i (conj out {:kind :string :value value :dynamic dynamic})))
            (or (<= (int \a) (int c) (int \z)) (<= (int \A) (int c) (int \Z)) (= c \_))
            (let [end (loop [j (inc i)]
                        (if (and (< j n) (or (<= (int \a) (int (at j)) (int \z))
                                               (<= (int \A) (int (at j)) (int \Z))
                                               (<= (int \0) (int (at j)) (int \9)) (= (at j) \_)))
                          (recur (inc j)) j))]
              (recur end (conj out {:kind :word :value (subs source i end)})))
            (and (<= 33 (int c) 126) (not (#{\\ \$} c)))
            (recur (inc i) (conj out {:kind :other :value (str c)}))
            :else (fail! "E_SOURCE_LEXICAL")))))))

(defn recognize! [source]
  (let [ts (tokens source) cursor (atom 0) stage-ids (atom #{}) total-steps (atom 0) total-bytes (atom 0)]
    (letfn [(peek-t [] (nth ts @cursor {:kind :eof}))
            (kind [] (:kind (peek-t)))
            (take-t [] (let [t (peek-t)] (swap! cursor inc) t))
            (skip-lf [] (while (= :lf (kind)) (take-t)))
            (skip-seps [] (while (#{:lf \;} (kind)) (take-t)))
            (expect [k code] (when-not (= k (kind)) (fail! code)) (take-t))
            (word [s code] (let [t (expect :word code)] (when-not (= s (:value t)) (fail! code))))
            (open [code] (skip-lf) (expect \{ code) (skip-seps))
            (boundary [code] (when-not (#{:lf \; \}} (kind)) (fail! code)) (skip-seps))
            (literal [argument-code dynamic-code]
              (let [t (expect :string argument-code)]
                (when (:dynamic t) (fail! dynamic-code)) (:value t)))
            (step []
              (word "sh" "E_STEP_UNSUPPORTED")
              (let [paren (= \( (kind))
                    _ (when paren (take-t) (skip-lf))
                    script (literal "E_STEP_ARGUMENT" "E_STEP_DYNAMIC")
                    _ (when paren (skip-lf) (expect \) "E_STEP_ARGUMENT"))
                    bytes (byte-count script)]
                (when (or (zero? bytes) (> bytes 4096) (str/includes? script "\u0000")) (fail! "E_STEP_ARGUMENT"))
                (when (str/starts-with? script "#!") (fail! "E_SHELL_SHEBANG_UNSUPPORTED"))
                (when (> (swap! total-steps inc) 64) (fail! "E_STEP_LIMIT"))
                (when (> (swap! total-bytes + bytes) 4096) (fail! "E_STEP_ARGUMENT"))
                (boundary "E_STEP_UNSUPPORTED")
                {:program "/bin/sh" :args ["-xe" "-c" script]}))
            (stage []
              (word "stage" "E_STAGE_UNSUPPORTED")
              (expect \( "E_STAGE_ARGUMENT") (skip-lf)
              (let [name (literal "E_STAGE_ARGUMENT" "E_STAGE_DYNAMIC")
                    _ (skip-lf)
                    _ (expect \) "E_STAGE_ARGUMENT")
                    id (stage-id name)]
                (when (contains? @stage-ids id) (fail! "E_STAGE_DUPLICATE"))
                (swap! stage-ids conj id)
                (open "E_STAGE_BODY")
                (word "steps" "E_STAGE_BODY") (open "E_STAGE_BODY")
                (let [steps (loop [out []]
                              (if (= \} (kind)) out (recur (conj out (step)))))]
                  (when (empty? steps) (fail! "E_STAGE_BODY"))
                  (expect \} "E_STAGE_BODY") (skip-seps) (expect \} "E_STAGE_BODY")
                  (boundary "E_STAGE_UNSUPPORTED")
                  {:id id :name name :steps steps})))]
      (skip-seps) (word "pipeline" "E_DECLARATIVE_ROOT") (open "E_DECLARATIVE_ROOT")
      (word "agent" "E_DIRECTIVE_UNSUPPORTED") (word "any" "E_AGENT_UNSUPPORTED")
      (boundary "E_DIRECTIVE_UNSUPPORTED")
      (word "stages" "E_DIRECTIVE_UNSUPPORTED") (open "E_STAGES_BODY")
      ;; Bounds take precedence over peer-separator errors. Count only stage
      ;; call tokens at this block depth; quoted payloads/comments are opaque.
      (loop [index @cursor depth 0 stage-count 0]
        (let [t (nth ts index {:kind :eof}) k (:kind t)]
          (when-not (or (= :eof k) (and (= \} k) (zero? depth)))
            (let [stage-count (if (and (zero? depth) (= :word k) (= "stage" (:value t))
                                       (= \( (:kind (nth ts (inc index) {:kind :eof}))))
                                (inc stage-count) stage-count)]
              (when (> stage-count 32) (fail! "E_STAGES_BODY"))
              (recur (inc index) (case k \{ (inc depth) \} (dec depth) depth) stage-count)))))
      (let [stages (loop [out []]
                     (if (= \} (kind)) out
                       (let [next-stage (stage)]
                         (when (= 32 (count out)) (fail! "E_STAGES_BODY"))
                         (recur (conj out next-stage)))))]
        (when (empty? stages) (fail! "E_STAGES_BODY"))
        (expect \} "E_STAGES_BODY") (skip-seps) (expect \} "E_DIRECTIVE_UNSUPPORTED")
        (skip-seps) (expect :eof "E_DECLARATIVE_ROOT")
        {:agent "any" :stages stages}))))
