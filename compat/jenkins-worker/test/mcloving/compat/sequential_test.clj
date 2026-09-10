(ns mcloving.compat.sequential-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [mcloving.compat.profile :as profile]
            [mcloving.compat.main :as main]
            [mcloving.compat.protocol :as legacy]
            [mcloving.compat.sequential-lexer :as lexer]
            [mcloving.compat.sequential-compiler :as compiler]
            [mcloving.compat.sequential-protocol :as protocol])
  (:import (java.io ByteArrayInputStream)
           (java.nio.file Files)
           (groovy.json JsonSlurper)
           (org.codehaus.groovy.ast.builder AstBuilder)))

(def target {:profile-sha256 "feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271"})
(defn b [s] (.getBytes ^String s "UTF-8"))
(defn code [f] (try (f) nil (catch clojure.lang.ExceptionInfo e (:code (ex-data e)))))
(defn pipeline [steps] (str "pipeline { agent any; stages { stage('Build') { steps { " steps " } } } }\n"))
(defn context [source] {:document-id "nonallowlisted-case" :origin "authored:sequential-tests"
                        :origin-kind :authored-document :schema "mcloving.jenkins.source-document/1"
                        :source-sha256 (profile/sha256-bytes source)})
(defn request [source] {:protocol protocol/protocol-version :operation :compile-sequential
                        :request-id "test:case" :source-path "/input/Jenkinsfile"
                        :source-context (context source)
                        :target-profile-sha256 (:profile-sha256 target)
                        :target-contract-sha256 compiler/contract-sha256})
(defn response
  ([source] (response source (request source)))
  ([source req]
   (with-redefs [legacy/current-environment-keys (constantly #{"LANG" "TZ"})
                 protocol/source-bytes! (constantly source)]
     (protocol/handle-request target req (protocol/canonical-bytes req)))))
(defn scripts [parsed] (mapv #(get-in % [:args 2]) (mapcat :steps (:stages parsed))))

(deftest actual-parser-and-contract-bytes-are-pinned
  (let [jar (io/file (.toURI (.getLocation (.getCodeSource (.getProtectionDomain AstBuilder)))))]
    (is (= "de65260cf2070442e99882f2f3d72e7531725c1e6a257446cc0cea525c607bd0"
           (profile/sha256-bytes (Files/readAllBytes (.toPath jar))))))
  (is (= compiler/contract-sha256
         (profile/sha256-bytes (Files/readAllBytes (.toPath (io/file "../../docs/architecture/JENKINS_SEQUENTIAL_DECLARATIVE_V2.md")))))))

(deftest fixed-contract-population
  (let [fixtures (get (.parseText (JsonSlurper.) (slurp "fixtures/sequential-v1/manifest.json")) "fixtures")]
    (is (= 23 (count fixtures)))
    (doseq [fixture fixtures]
      (testing (get fixture "id")
        (let [source (Files/readAllBytes (.toPath (io/file "../.." (get fixture "source_path"))))
              expected (get fixture "expected") result (response source)]
          (is (= (get fixture "source_sha256") (profile/sha256-bytes source)))
          (if (= "supported" (get expected "compilation"))
            (do (is (= :compiled (:status result)))
                (let [parsed (compiler/parse! source)]
                  (is (= (mapv #(get % "name") (get expected "stages")) (mapv :name (:stages parsed))))
                  (is (= (vec (mapcat #(map (fn [step] (get step "script_utf8")) (get % "steps")) (get expected "stages")))
                         (scripts parsed)))))
            (do (is (= (keyword (get expected "compilation")) (:status result)))
                (is (= (get expected "diagnostic") (get-in result [:diagnostic :code]))))))))))

(deftest four-quote-forms-and-all-permitted-escapes
  (doseq [delimiter ["'" "\"" "'''" "\"\"\""]
          [spelling expected] [["\\\\" "\\"] ["\\'" "'"] ["\\\"" "\""] ["\\$" "$"]
                               ["\\n" "\n"] ["\\r" "\r"] ["\\t" "\t"] ["\\b" "\b"] ["\\f" "\f"]]]
    (let [source (pipeline (str "sh(" delimiter "printf " spelling delimiter ")"))]
      (is (= [(str "printf " expected)] (scripts (compiler/parse! (b source)))))))
  (doseq [delim ["'''" "\"\"\""]]
    (is (= ["printf first\nprintf second"]
           (scripts (compiler/parse! (b (pipeline (str "sh " delim "printf first\nprintf second" delim)))))))))

(deftest separator-and-call-continuation-rules
  (doseq [sep [";" ";;;" "\n" "// comment\n" "/* comment */\n"]]
    (is (= ["printf one" "printf two"]
           (scripts (compiler/parse! (b (pipeline (str "sh 'printf one'" sep "sh('printf two')"))))))))
  (is (= ["printf x"] (scripts (compiler/parse! (b "pipeline\n{ agent any; stages\n{ stage(\n'Build'\n)\n{ steps\n{ sh(\n'printf x'\n) } } } }")))))
  (doseq [steps ["sh 'one' sh 'two'" "sh 'one' /* comment\n */ sh 'two'"
                 "sh\n'one'" "sh\n('one')"]]
    (is (some? (code #(compiler/parse! (b (pipeline steps))))))))

(deftest lexical-exclusions-never-enter-conversion
  (doseq [outside ["\\" "$" "\u00a0" "\u000b" "é"]]
    (is (= "E_SOURCE_LEXICAL" (code #(lexer/recognize! (str outside (pipeline "sh 'x'")))))))
  (is (= "E_DIRECTIVE_UNSUPPORTED" (code #(compiler/parse! (b "pipeline { stages {} }")))))
  ;; Substituting the AST reader proves excluded forms stop before conversion.
  (let [parse-var (ns-resolve 'mcloving.compat.sequential-compiler 'parse-pipeline!)]
    (with-redefs-fn {parse-var (fn [_] (throw (AssertionError. "excluded source reached CONVERSION")))}
      #(doseq [source ["node { sh 'printf x' }" "import java.lang.String\nnode {}"
                       "package example\nnode {}" "@Deprecated class Example {}"
                       "def x = 'plain'" (pipeline "this.sh 'printf x'")
                       (pipeline "sh /printf x/") (pipeline "sh $/printf x/$")
                       (pipeline "sh '\\u0041'")
                       "pipeline { -> agent any; stages {} }"]]
         (is (some? (code (fn [] (compiler/parse! (b source))))))))))

(deftest unicode-normalization-and-scalar-rendering
  (is (= "a--b" (lexer/stage-id "A- B")))
  (is (= "a---b" (lexer/stage-id "A-- B")))
  (is (= "a--b" (lexer/stage-id "A-  B")))
  (is (= "build" (lexer/stage-id "Build")))
  (is (= (apply str (repeat 96 "a")) (lexer/stage-id (apply str (repeat 96 "A")))))
  (is (= "E_STAGE_NAME" (code #(lexer/stage-id (apply str (repeat 97 "a"))))))
  (is (= "a" (lexer/stage-id (str "a" (apply str (repeat 47 "é"))))))
  (is (= "E_STAGE_NAME" (code #(lexer/stage-id (str "a" (apply str (repeat 48 "é")))))))
  (is (= "E_STAGE_NAME" (code #(lexer/stage-id "K"))))
  (is (= "\"\\U0001f642\\u2028\\u0085\\u007f\"" (compiler/yaml-string "🙂\u2028\u0085\u007f")))
  (is (= ["printf café🙂\u2028\u0085\u007f"]
         (scripts (compiler/parse! (b (pipeline "sh 'printf café🙂\u2028\u0085\u007f'")))))))

(deftest unicode-preprocessing-and-literal-backslash
  (is (= ["printf \\u0041"] (scripts (compiler/parse! (b (pipeline "sh 'printf \\\\u0041'"))))))
  (doseq [prefix ["// \\u0041\n" "/* \\u0041 */\n"]]
    (is (= "E_SOURCE_LEXICAL" (code #(compiler/parse! (b (str prefix (pipeline "sh 'printf x'"))))))))
  (is (= :compiled (:status (response (b (str "// \\\\u0041\n" (pipeline "sh 'printf x'"))))))))

(deftest source-and-decoded-byte-bounds
  (doseq [source [(byte-array [(unchecked-byte 255)]) (b "\ufeffpipeline {}") (b "pipeline {}\r\n") (b "\u0000")]]
    (is (= "E_SOURCE_TEXT" (code #(compiler/parse! source)))))
  (is (= "E_SOURCE_TOO_LARGE" (code #(compiler/parse! (b (apply str (repeat 16385 "x")))))))
  (let [base (pipeline "sh 'x'") padded (str base (apply str (repeat (- 16384 (count base)) " ")))]
    (is (= ["x"] (scripts (compiler/parse! (b padded))))))
  (is (= [(apply str (repeat 4096 "x"))]
         (scripts (compiler/parse! (b (pipeline (str "sh '" (apply str (repeat 4096 "x")) "'")))))))
  (is (= "E_STEP_ARGUMENT" (code #(compiler/parse! (b (pipeline (str "sh '" (apply str (repeat 2049 "é")) "'")))))))
  (is (= "E_STEP_ARGUMENT" (code #(compiler/parse! (b (pipeline (str "sh '" (apply str (repeat 2048 "x")) "'; sh '" (apply str (repeat 2049 "x")) "'")))))))
  (is (= 64 (count (scripts (compiler/parse! (b (pipeline (str/join ";" (repeat 64 "sh 'x'")))))))))
  (is (= "E_STEP_LIMIT" (code #(compiler/parse! (b (pipeline (str/join ";" (repeat 65 "sh 'x'"))))))))
  (let [stage (fn [i] (str "stage('Stage" i "') { steps { sh 'x' } }"))
        stages-source (fn [n separator] (str "pipeline { agent any; stages { "
                                            (str/join separator (map stage (range n))) " } }"))]
    (is (= 32 (count (:stages (compiler/parse! (b (stages-source 32 ";")))))))
    (is (= "E_STAGES_BODY" (code #(compiler/parse! (b (stages-source 33 ";"))))))
    (is (= "E_STAGES_BODY" (code #(compiler/parse! (b (stages-source 33 " "))))))
    (is (= "E_STAGE_UNSUPPORTED" (code #(compiler/parse! (b (stages-source 2 " "))))))
    (is (= "E_STAGE_DUPLICATE" (code #(compiler/parse! (b "pipeline { agent any; stages { stage('Build') { steps { sh 'x' } }; stage('build') { steps { sh 'y' } } } }")))))))

(deftest request-context-and-version-bindings
  (let [source (b (pipeline "sh 'printf x'")) req (request source)]
    (is (= :compiled (:status (response source))))
    (is (= "E_SOURCE_PATH" (code #(protocol/source-bytes! (assoc req :source-path "/wrong/path")))) )
    (doseq [[changed expected] [[(assoc req :unexpected true) "E_REQUEST_FIELDS"]
                                [(assoc req :protocol legacy/protocol-version) "E_PROTOCOL_VERSION"]
                                [(assoc req :request-id "bad id") "E_REQUEST_ID"]
                                [(assoc req :target-profile-sha256 (apply str (repeat 64 "0"))) "E_TARGET_PROFILE"]
                                [(assoc req :target-contract-sha256 (apply str (repeat 64 "0"))) "E_TARGET_CONTRACT"]
                                [(assoc-in req [:source-context :source-sha256] (apply str (repeat 64 "0"))) "E_SOURCE_DIGEST"]
                                [(assoc-in req [:source-context :document-id] "bad:document") "E_DOCUMENT_CONTEXT"]
                                [(assoc-in req [:source-context :origin-kind] :jenkins-job) "E_DOCUMENT_CONTEXT"]
                                [(assoc-in req [:source-context :job-enabled] false) "E_DOCUMENT_CONTEXT"]]]
      (is (= expected (get-in (response source changed) [:diagnostic :code]))))
    (is (= :compiled (:status (response source (assoc-in req [:source-context :origin-kind] :corpus-reference)))))
    (is (= "E_ENV_AUTHORITY"
           (get-in (with-redefs [legacy/current-environment-keys (constantly #{"SECRET_TOKEN"})]
                     (protocol/handle-request target req (protocol/canonical-bytes req))) [:diagnostic :code])))))

(deftest canonical-raw-request-and-legacy-reader
  (let [source (b (pipeline "sh 'x'")) req (request source) canonical (protocol/canonical-bytes req)]
    (doseq [raw [(b (legacy/canonical-edn req)) (b (str (legacy/canonical-edn req) "\n\n"))
                 (b (str " " (legacy/canonical-edn req) "\n"))]]
      (is (= "E_REQUEST_INVALID" (get-in (protocol/handle-request target req raw) [:diagnostic :code]))))
    (let [loaded (legacy/read-request-with-bytes! (ByteArrayInputStream. canonical))]
      (is (= req (:request loaded)))
      (is (= (seq canonical) (seq (:bytes loaded)))))
    (is (= req (legacy/read-request! (ByteArrayInputStream. (b (legacy/canonical-edn req))))))
    (let [events (atom [])]
      (with-redefs [profile/load-and-verify! (fn [] (swap! events conj :profile) target)
                    legacy/read-request-with-bytes! (fn [_] (swap! events conj :input) {:request req :bytes canonical})
                    protocol/handle-request (fn [p r raw]
                                              (is (= target p)) (is (= req r))
                                              (is (= (seq canonical) (seq raw)))
                                              {:status :compiled})]
        (is (= "{:status :compiled}\n" (with-out-str (main/-main))))
        (is (= [:profile :input] @events))))))

(deftest disabled-artifact-and-determinism
  (let [source (b (pipeline "sh 'printf café🙂'")) a (response source) b (response source)
        result (:result a) artifact (:definition-yaml result)]
    (is (= :compiled (:status a)))
    (is (= (seq (protocol/canonical-bytes a)) (seq (protocol/canonical-bytes b))))
    (is (every? false? (vals (:authority a))))
    (is (= "linux" (get-in a [:result :agent-mapping :mcloving-platform])))
    (is (str/includes? artifact "\nstate: disabled\n"))
    (is (not-any? #(str/includes? artifact %) ["generation:" "effective_time:" "actor:" "inventory_fingerprint:"]))
    (is (= (:definition-yaml-sha256 result) (compiler/sha artifact)))
    (is (str/includes? artifact (str "  contract_sha256: \"" compiler/contract-sha256 "\"\n")))
    (is (= (:pipeline-yaml-sha256 result) (compiler/sha (:pipeline-yaml result))))
    (is (every? #(<= (int %) 127) (legacy/canonical-edn a)))))

(deftest ast-agreement-and-response-capacity-fail-closed
  (let [parse-var (ns-resolve 'mcloving.compat.sequential-compiler 'parse-pipeline!)
        source (b (pipeline "sh 'x'"))]
    (with-redefs-fn {parse-var (fn [_] {:agent "any" :stages []})}
      #(is (= "E_AST_AGREEMENT" (get-in (response source) [:diagnostic :code]))))
    (with-redefs [compiler/compile! (fn [& _] {:padding (apply str (repeat 65536 "x"))})]
      (let [result (response source)]
        (is (= :rejected (:status result)))
        (is (= "E_RESPONSE_TOO_LARGE" (get-in result [:diagnostic :code])))
        (is (< (alength (protocol/canonical-bytes result)) 65536))))))

(deftest explicit-diagnostic-precedence-preserves-runnable-boundary
  (let [cases (.parseText (JsonSlurper.) (slurp "fixtures/diagnostic-v2/cases.json"))]
    (is (= 10 (count cases)))
    (doseq [case cases]
      (testing (get case "id")
        (let [result (response (b (get case "source")))]
          (is (= (keyword (get case "status")) (:status result)))
          (is (= (get case "code") (get-in result [:diagnostic :code])))
          (is (nil? (:result result)))
          (is (every? false? (vals (:authority result)))))))))
