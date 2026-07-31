(ns mcloving.compat.compiler
  "A deliberately tiny, parse-only Jenkins Declarative compiler.

  Groovy is used only to construct an AST at CONVERSION phase. No script,
  closure, method, Jenkins extension, or user source is ever evaluated."
  (:require [clojure.string :as str]
            [mcloving.compat.profile :as profile])
  (:import (java.nio.charset StandardCharsets)
           (org.codehaus.groovy.ast.expr ArgumentListExpression ClosureExpression
                                         ConstantExpression MethodCallExpression
                                         VariableExpression)
           (org.codehaus.groovy.ast.stmt BlockStatement ExpressionStatement)
           (org.codehaus.groovy.ast.builder AstBuilder)
           (org.codehaus.groovy.control CompilePhase)))

(def admitted-source-sha256
  "666ac2275ea75730e27cf7b565d757691b094c508355adc0199d745278a23100")
(def admitted-job-id "corpus-052-cinqict_jenkinsdev")
(def admitted-job-generation
  "e76362bbc8e899510b8498808ffd0d2f83bb64d3215cf2c5b31690895f251d97")
(def admitted-inventory-fingerprint
  "b1c2f81c74ec0ffc36971f358f920b2d0775c6009f474bea924448cd2a1915c1")
(def admitted-reason "offline-frozen-source-state")
(def admitted-actor "jenkins/system")
(def admitted-effective-time "2026-07-31T06:44:17Z")
(def max-stages 32)
(def max-steps 256)
(def max-shell-bytes 16384)

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

(defn- yaml-string
  [value]
  ;; Clojure's printed string escapes are accepted by McLoving strict YAML.
  (pr-str value))

(defn- stage-id
  [name]
  (let [identifier (-> name
                       str/lower-case
                       (str/replace #"[^a-z0-9._-]+" "-")
                       (str/replace #"^-+|-+$" ""))]
    (when (or (str/blank? identifier)
              (> (count identifier) 96))
      (reject! "E_STAGE_NAME"))
    identifier))

(defn- parse-step!
  [statement]
  (let [{:keys [arguments]} (named-call! statement "sh" "E_STEP_UNSUPPORTED")]
    (when-not (= 1 (count arguments))
      (reject! "E_STEP_ARGUMENT"))
    (let [script (constant-string! (first arguments) "E_STEP_DYNAMIC")
          bytes (count (.getBytes script StandardCharsets/UTF_8))]
      (when (or (zero? bytes) (> bytes max-shell-bytes))
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
      (when (or (empty? step-statements) (> (count step-statements) max-steps))
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
                        (> (count stage-statements) max-stages))
                (reject! "E_STAGES_BODY"))
              (let [stages (mapv parse-stage! stage-statements)
                    identifiers (mapv :id stages)]
                (when-not (= (count identifiers) (count (distinct identifiers)))
                  (reject! "E_STAGE_DUPLICATE"))
                {:agent "any" :stages stages}))))))))

(defn- pipeline-yaml
  [job-id stages]
  (str
   "version: 1\n"
   "name: " (yaml-string job-id) "\n"
   "stages:\n"
   (apply str
          (for [{:keys [id name steps]} stages]
            (str
             "  - id: " (yaml-string id) "\n"
             "    name: " (yaml-string name) "\n"
             "    steps:\n"
             (apply str
                    (for [{:keys [program args]} steps]
                      (str
                       "      - process:\n"
                       "          program: " (yaml-string program) "\n"
                       "          args: ["
                       (str/join ", " (map yaml-string args))
                       "]\n"))))))))

(defn- jobstate-yaml
  [request compiler-id profile]
  (str
   "version: 1\n"
   "schema: mcloving.jenkins.jobstate-import\n"
   "job_id: " (yaml-string (:job-id request)) "\n"
   "state: disabled\n"
   "generation: " (yaml-string (:job-generation request)) "\n"
   "reason: " (yaml-string (:job-reason request)) "\n"
   "actor: " (yaml-string (:job-actor request)) "\n"
   "effective_time: " (yaml-string (:job-effective-time request)) "\n"
   "provenance:\n"
   "  controller: " (yaml-string (:controller profile)) "\n"
   "  inventory_fingerprint: "
   (yaml-string (:inventory-fingerprint request)) "\n"
   "  source_sha256: " (yaml-string (:source-sha256 request)) "\n"
   "  compiler: " (yaml-string compiler-id) "\n"
   "  compiler_profile_sha256: "
   (yaml-string (:profile-sha256 profile)) "\n"))

(defn compile-admitted!
  [compiler-id profile request source]
  (when-not (and (= admitted-source-sha256 (:source-sha256 request))
                 (= admitted-job-id (:job-id request))
                 (= admitted-job-generation (:job-generation request))
                 (= false (:job-enabled request))
                 (= admitted-reason (:job-reason request))
                 (= admitted-actor (:job-actor request))
                 (= admitted-effective-time (:job-effective-time request))
                 (= admitted-inventory-fingerprint
                    (:inventory-fingerprint request))
                 (= admitted-inventory-fingerprint
                    (:snapshot-fingerprint profile)))
    (reject! "E_SOURCE_NOT_ADMITTED"))
  (let [{:keys [agent stages]} (parse-pipeline! source)
        pipeline (pipeline-yaml (:job-id request) stages)
        jobstate (jobstate-yaml request compiler-id profile)]
    (sorted-map
     :agent-mapping
     (sorted-map
      :effect-authority false
      :jenkins-selector agent
      :mcloving-platform "any"
      :trust-pool "migration-deny-authority")
     :jobstate-yaml jobstate
     :jobstate-yaml-sha256
     (profile/sha256-bytes (.getBytes jobstate StandardCharsets/UTF_8))
     :pipeline-yaml pipeline
     :pipeline-yaml-sha256
     (profile/sha256-bytes (.getBytes pipeline StandardCharsets/UTF_8))
     :semantic
     (sorted-map
      :stages (count stages)
      :steps (reduce + (map #(count (:steps %)) stages))))))
