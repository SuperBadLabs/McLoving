(ns mcloving.compat.sequential-protocol
  "Additive bounded version 2 envelope. Output is disabled and deny-authority."
  (:require [mcloving.compat.protocol :as legacy]
            [mcloving.compat.profile :as profile]
            [mcloving.compat.sequential-compiler :as compiler]
            [mcloving.compat.sequential-lexer :as lexer])
  (:import (java.io ByteArrayOutputStream)
           (java.nio.charset StandardCharsets)
           (java.nio.file Files Paths LinkOption StandardOpenOption)
           (java.util Arrays)))

(def protocol-version "mcloving.jenkins.compiler/2")
(def unsupported-codes
  #{"E_SOURCE_LEXICAL" "E_DECLARATIVE_ROOT" "E_DIRECTIVE_UNSUPPORTED"
    "E_AGENT_UNSUPPORTED" "E_STAGES_BODY" "E_STAGE_UNSUPPORTED" "E_STAGE_ARGUMENT"
    "E_STAGE_DYNAMIC" "E_STAGE_NAME" "E_STAGE_DUPLICATE" "E_STAGE_BODY"
    "E_STEP_UNSUPPORTED" "E_STEP_ARGUMENT" "E_STEP_DYNAMIC" "E_STEP_LIMIT"
    "E_SHELL_SHEBANG_UNSUPPORTED"})
(defn utf8-bytes [^String s] (.getBytes s StandardCharsets/UTF_8))
(defn canonical-bytes [value] (utf8-bytes (str (legacy/canonical-edn value) "\n")))
(defn- valid-sha? [s] (and (string? s) (boolean (re-matches #"[0-9a-f]{64}" s))))
(defn- identifier? [s bound pattern]
  (and (string? s) (<= 1 (count s) bound) (boolean (re-matches pattern s))))
(defn validate-context! [context]
  (when-not (and (map? context)
                (= #{:document-id :origin :origin-kind :schema :source-sha256} (set (keys context)))
                (= "mcloving.jenkins.source-document/1" (:schema context))
                (#{:authored-document :corpus-reference} (:origin-kind context))
                (identifier? (:document-id context) 128 #"[A-Za-z0-9][A-Za-z0-9._-]*")
                (string? (:origin context))
                (boolean (re-matches #"[\x20-\x7e]{1,512}" (:origin context)))
                (valid-sha? (:source-sha256 context)))
    (lexer/fail! "E_DOCUMENT_CONTEXT"))
  (let [encoded (canonical-bytes context)]
    (when (> (alength encoded) 2048) (lexer/fail! "E_DOCUMENT_CONTEXT"))
    (profile/sha256-bytes encoded)))

(defn source-bytes!
  "Read only the fixed mounted source, bounded to the legacy transport ceiling."
  [request]
  (when-not (= "/input/Jenkinsfile" (:source-path request)) (lexer/fail! "E_SOURCE_PATH"))
  (let [path (Paths/get "/input/Jenkinsfile" (make-array String 0))]
    (when (or (Files/isSymbolicLink path)
              (not (Files/isRegularFile path (into-array LinkOption [LinkOption/NOFOLLOW_LINKS]))))
      (lexer/fail! "E_SOURCE_TYPE"))
    (try
      (with-open [input (Files/newInputStream path (into-array java.nio.file.OpenOption
                                                            [StandardOpenOption/READ LinkOption/NOFOLLOW_LINKS]))]
        (let [out (ByteArrayOutputStream.) buffer (byte-array 8192)]
          (loop [total 0]
            (let [n (.read input buffer)]
              (if (neg? n) (.toByteArray out)
                (let [total (+ total n)]
                  (when (> total 262144) (lexer/fail! "E_SOURCE_TOO_LARGE"))
                  (.write out buffer 0 n) (recur total)))))))
      (catch java.io.IOException _ (lexer/fail! "E_SOURCE_TYPE")))))

(defn rejection [throwable]
  {:authority legacy/authority :compiler compiler/compiler-id :protocol protocol-version
   :status :rejected
   :diagnostic {:code (or (:code (ex-data throwable)) "E_WORKER_INTERNAL")
                :message "request rejected without execution authority"}})

(defn- compile-request! [profile request raw]
  (when-not (Arrays/equals ^bytes raw ^bytes (canonical-bytes request)) (lexer/fail! "E_REQUEST_INVALID"))
  (when-not (= #{:operation :protocol :request-id :source-context :source-path
                :target-profile-sha256 :target-contract-sha256} (set (keys request)))
    (lexer/fail! "E_REQUEST_FIELDS"))
  (when-not (= protocol-version (:protocol request)) (lexer/fail! "E_PROTOCOL_VERSION"))
  (when-not (= :compile-sequential (:operation request)) (lexer/fail! "E_OPERATION"))
  (when-not (identifier? (:request-id request) 96 #"[A-Za-z0-9][A-Za-z0-9._:-]*") (lexer/fail! "E_REQUEST_ID"))
  (when-not (= (:profile-sha256 profile) (:target-profile-sha256 request)) (lexer/fail! "E_TARGET_PROFILE"))
  (when-not (= compiler/contract-sha256 (:target-contract-sha256 request)) (lexer/fail! "E_TARGET_CONTRACT"))
  (let [context (:source-context request)
        context-sha (validate-context! context)]
    (legacy/validate-environment!)
    (let [source (source-bytes! request) sha (profile/sha256-bytes source)]
      (when-not (= sha (:source-sha256 context)) (lexer/fail! "E_SOURCE_DIGEST"))
      (let [base {:authority legacy/authority :compiler compiler/compiler-id
                  :contract-sha256 compiler/contract-sha256 :protocol protocol-version
                  :request-id (:request-id request) :target-profile profile
                  :source-context context
                  :source {:bytes (alength source) :context-sha256 context-sha :sha256 sha}}]
        (try
          (assoc base :status :compiled :result (compiler/compile! profile context context-sha source))
          (catch clojure.lang.ExceptionInfo e
            (if (contains? unsupported-codes (:code (ex-data e)))
              (assoc base :status :unsupported
                     :diagnostic {:code (:code (ex-data e))
                                  :message "source is outside the currently admitted compiler subset"})
              (throw e))))))))

(defn handle-request
  "Keep reliable version-2 boundary failures in version 2; bound complete wire."
  [profile parsed-request raw-request-bytes]
  (let [result (try (compile-request! profile parsed-request raw-request-bytes)
                    (catch Throwable e (rejection e)))]
    (if (> (alength (canonical-bytes result)) 65536)
      (rejection (ex-info "bounded response exceeded" {:code "E_RESPONSE_TOO_LARGE"}))
      result)))
