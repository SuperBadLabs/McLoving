(ns mcloving.compat.sequential-compiler
  "Version 2 parse-only compiler: recognize fixed syntax before CONVERSION."
  (:require [clojure.string :as str]
            [mcloving.compat.sequential-lexer :as lexer]
            [mcloving.compat.profile :as profile])
  (:import (java.nio.charset StandardCharsets)
           (org.codehaus.groovy.ast.expr ArgumentListExpression ClosureExpression
                                         ConstantExpression MethodCallExpression VariableExpression)
           (org.codehaus.groovy.ast.stmt BlockStatement ExpressionStatement)
           (org.codehaus.groovy.ast.builder AstBuilder)
           (org.codehaus.groovy.control CompilePhase SourceUnit MultipleCompilationErrorsException)))

(def contract-sha256 "264436c57b3aa82810f7041515c924b38a5a5e4be1f60fb6987151d1e8336a41")
(def compiler-id "mcloving-jenkins-compiler-worker/2")
(defn- reject!
  [code]
  (throw (ex-info "source is outside the admitted compiler subset" {:code code})))

(defn- exact-class!
  [expected value code]
  (when-not (= expected (class value))
    (reject! code))
  value)

(defn- block-statements!
  [value code]
  (vec (.getStatements ^BlockStatement (exact-class! BlockStatement value code))))

(defn- call!
  [statement code]
  (let [expression (.getExpression
                    ^ExpressionStatement
                    (exact-class! ExpressionStatement statement code))
        call (exact-class! MethodCallExpression expression code)
        object (.getObjectExpression ^MethodCallExpression call)
        method (.getMethod ^MethodCallExpression call)
        arguments (.getArguments ^MethodCallExpression call)]
    (exact-class! VariableExpression object code)
    (when-not (= "this" (.getName ^VariableExpression object))
      (reject! code))
    (exact-class! ConstantExpression method code)
    (exact-class! ArgumentListExpression arguments code)
    {:arguments (vec (.getExpressions ^ArgumentListExpression arguments))
     :name (.getValue ^ConstantExpression method)}))

(defn- named-call!
  [statement expected code]
  (let [call (call! statement code)]
    (when-not (= expected (:name call))
      (reject! code))
    call))

(defn- closure-statements!
  [value code]
  (let [closure (exact-class! ClosureExpression value code)]
    (block-statements! (.getCode ^ClosureExpression closure) code)))

(defn- constant-string!
  [value code]
  (let [constant (exact-class! ConstantExpression value code)
        value (.getValue ^ConstantExpression constant)]
    (when-not (string? value)
      (reject! code))
    value))

(defn- stage-id [name] (lexer/stage-id name))

(defn- parse-step!
  [statement]
  (let [{:keys [arguments]} (named-call! statement "sh" "E_STEP_UNSUPPORTED")]
    (when-not (= 1 (count arguments))
      (reject! "E_STEP_ARGUMENT"))
    (let [script (constant-string! (first arguments) "E_STEP_DYNAMIC")
          bytes (count (.getBytes script StandardCharsets/UTF_8))]
      (when (or (zero? bytes) (> bytes 4096))
        (reject! "E_STEP_ARGUMENT"))
      {:program "/bin/sh"
       :args ["-xe" "-c" script]})))

(defn- parse-stage!
  [statement]
  (let [{:keys [arguments]} (named-call! statement "stage" "E_STAGE_UNSUPPORTED")]
    (when-not (= 2 (count arguments))
      (reject! "E_STAGE_ARGUMENT"))
    (let [name (constant-string! (first arguments) "E_STAGE_DYNAMIC")
          body (closure-statements! (second arguments) "E_STAGE_BODY")
          _ (when-not (= 1 (count body)) (reject! "E_STAGE_BODY"))
          steps-call (named-call! (first body) "steps" "E_STAGE_BODY")
          _ (when-not (= 1 (count (:arguments steps-call)))
              (reject! "E_STAGE_BODY"))
          step-statements (closure-statements!
                           (first (:arguments steps-call))
                           "E_STAGE_BODY")]
      (when (or (empty? step-statements) (> (count step-statements) 64))
        (reject! "E_STAGE_BODY"))
      {:id (stage-id name)
       :name name
       :steps (mapv parse-step! step-statements)})))

(defn- parse-pipeline!
  [source]
  (let [nodes (vec (.buildFromString
                    (AstBuilder.)
                    CompilePhase/CONVERSION
                    true
                    source))]
    (when-not (= 1 (count nodes))
      (reject! "E_DECLARATIVE_ROOT"))
    (let [root-statements (block-statements! (first nodes) "E_DECLARATIVE_ROOT")]
      (when-not (= 1 (count root-statements))
        (reject! "E_DECLARATIVE_ROOT"))
      (let [pipeline-call (named-call!
                           (first root-statements)
                           "pipeline"
                           "E_DECLARATIVE_ROOT")]
        (when-not (= 1 (count (:arguments pipeline-call)))
          (reject! "E_DECLARATIVE_ROOT"))
        (let [body (closure-statements!
                    (first (:arguments pipeline-call))
                    "E_DECLARATIVE_ROOT")]
          (when-not (= 2 (count body))
            (reject! "E_DIRECTIVE_UNSUPPORTED"))
          (let [agent-call (named-call! (first body) "agent" "E_AGENT_UNSUPPORTED")
                stages-call (named-call! (second body) "stages" "E_DIRECTIVE_UNSUPPORTED")]
            (when-not (and (= 1 (count (:arguments agent-call)))
                           (= VariableExpression
                              (class (first (:arguments agent-call))))
                           (= "any"
                              (.getName
                               ^VariableExpression
                               (first (:arguments agent-call)))))
              (reject! "E_AGENT_UNSUPPORTED"))
            (when-not (= 1 (count (:arguments stages-call)))
              (reject! "E_STAGES_BODY"))
            (let [stage-statements (closure-statements!
                                    (first (:arguments stages-call))
                                    "E_STAGES_BODY")]
              (when (or (empty? stage-statements)
                        (> (count stage-statements) 32))
                (reject! "E_STAGES_BODY"))
              (let [stages (mapv parse-stage! stage-statements)
                    identifiers (mapv :id stages)]
                (when-not (= (count identifiers) (count (distinct identifiers)))
                  (reject! "E_STAGE_DUPLICATE"))
                {:agent "any" :stages stages}))))))))

(defn parse! [bytes]
  (let [source (lexer/source-text! bytes)]
    ;; Lexically excluded source has no full-Groovy validity claim. Determine
    ;; that boundary before full parsing, using the same precedence as the
    ;; independent recognizer. Every eligible source still requires both the
    ;; Groovy parse and AST agreement below before it can be compiled.
    (lexer/tokens source)
    ;; SourceUnit.parse is PARSING only. Never convert arbitrary excluded forms.
    (try
      (let [unit (SourceUnit/create "Jenkinsfile" source)]
        (.parse unit)
        (when (.hasErrors (.getErrorCollector unit)) (lexer/fail! "E_SOURCE_PARSE")))
      (catch MultipleCompilationErrorsException _ (lexer/fail! "E_SOURCE_PARSE")))
    (let [recognized (lexer/recognize! source)
          ast (try (parse-pipeline! source)
                   (catch clojure.lang.ExceptionInfo _ (lexer/fail! "E_AST_AGREEMENT")))]
      (when-not (= recognized ast) (lexer/fail! "E_AST_AGREEMENT"))
      recognized)))

(defn yaml-string [^String value]
  (let [out (StringBuilder. "\"")]
    (doseq [cp (.toArray (.codePoints value))]
      (.append out ^String
               (case cp
                 34 "\\\"" 92 "\\\\" 8 "\\b" 12 "\\f" 10 "\\n" 13 "\\r" 9 "\\t"
                 (cond
                   (<= 32 cp 126) (str (char cp))
                   (<= cp 65535) (format "\\u%04x" cp)
                   :else (format "\\U%08x" cp)))))
    (.append out "\"") (str out)))

(defn pipeline-yaml [document-id stages]
  (str "version: 1\nname: " (yaml-string document-id) "\nstages:\n"
       (apply str
              (for [{:keys [id name steps]} stages]
                (str "  - id: " (yaml-string id) "\n    name: " (yaml-string name) "\n    steps:\n"
                     (apply str
                            (for [{:keys [program args]} steps]
                              (str "      - process:\n          program: " (yaml-string program)
                                   "\n          args: [" (str/join ", " (map yaml-string args)) "]\n"))))))))

(defn sha [s] (profile/sha256-bytes (.getBytes ^String s StandardCharsets/UTF_8)))
(defn definition-yaml [context context-sha target-profile-sha pipeline-sha]
  (str "version: 1\nschema: mcloving.jenkins.disabled-document\ndefinition_id: "
       (yaml-string (:document-id context)) "\nstate: disabled\nsource:\n  context_sha256: "
       (yaml-string context-sha) "\n  origin_kind: " (yaml-string (name (:origin-kind context)))
       "\n  origin: " (yaml-string (:origin context)) "\n  sha256: " (yaml-string (:source-sha256 context))
       "\ncompilation:\n  compiler: " (yaml-string compiler-id)
       "\n  contract_sha256: " (yaml-string contract-sha256)
       "\n  target_profile_sha256: " (yaml-string target-profile-sha)
       "\n  pipeline_yaml_sha256: " (yaml-string pipeline-sha) "\n"))

(defn compile! [profile context context-sha bytes]
  (let [{:keys [stages]} (parse! bytes)
        pipeline (pipeline-yaml (:document-id context) stages)
        definition (definition-yaml context context-sha (:profile-sha256 profile) (sha pipeline))]
    {:agent-mapping {:effect-authority false :jenkins-selector "any"
                     :mcloving-platform "linux" :trust-pool "migration-deny-authority"}
     :definition-yaml definition :definition-yaml-sha256 (sha definition)
     :pipeline-yaml pipeline :pipeline-yaml-sha256 (sha pipeline)
     :semantic {:stages (count stages) :steps (reduce + (map #(count (:steps %)) stages))}}))
