;; Read-only fixture authoring check. CONVERSION constructs an AST; no source
;; evaluation, Jenkins model validation, compiler admission, or execution.
;; From compat/jenkins-worker:
;; clojure -M:foundation fixtures/sequential-v1/check_literals.clj ../..
(require '[clojure.java.io :as io])
(import '(groovy.json JsonSlurper)
        '(org.codehaus.groovy.ast.builder AstBuilder)
        '(org.codehaus.groovy.control CompilePhase MultipleCompilationErrorsException)
        '(org.codehaus.groovy.ast.expr ConstantExpression))

;; Match the actual loaded parser bytes, not only the requested dependency version.
(let [jar (io/file (.toURI (.getLocation (.getCodeSource (.getProtectionDomain AstBuilder)))))
      bytes (java.nio.file.Files/readAllBytes (.toPath jar))
      digest (.digest (java.security.MessageDigest/getInstance "SHA-256") bytes)]
  (assert (= "de65260cf2070442e99882f2f3d72e7531725c1e6a257446cc0cea525c607bd0"
             (format "%064x" (java.math.BigInteger. 1 digest)))
          "loaded Groovy parser does not match the pinned profile"))

(def root (or (first *command-line-args*)
              (throw (ex-info "expected repository root argument" {}))))
(def manifest
  (.parseText (JsonSlurper.)
              (slurp (io/file root "compat/jenkins-worker/fixtures/sequential-v1/manifest.json"))))
(defn arguments [statement]
  (vec (.getExpressions (.getArguments (.getExpression statement)))))
(defn body [closure] (vec (.getStatements (.getCode closure))))
(defn parse-source [fixture]
  (.buildFromString (AstBuilder.) CompilePhase/CONVERSION true
                    (slurp (io/file root (get fixture "source_path")))))
(defn source-stages [fixture]
  (let [ast (parse-source fixture)
        pipeline (first (.getStatements (first ast)))
        directives (body (first (arguments pipeline)))
        stages (body (first (arguments (second directives))))]
    (mapv (fn [stage]
            (let [[name closure] (arguments stage)
                  steps (body (first (arguments (first (body closure)))))]
              [(.getValue name)
               (mapv (fn [step]
                       (let [arg (first (arguments step))]
                         (assert (= ConstantExpression (class arg)))
                         (.getValue arg)))
                     steps)]))
          stages)))
(def supported
  (filter #(= "supported" (get-in % ["expected" "compilation"]))
          (get manifest "fixtures")))
(doseq [fixture supported]
  (let [expected (mapv (fn [stage]
                         [(get stage "name") (mapv #(get % "script_utf8")
                                                  (get stage "steps"))])
                       (get-in fixture ["expected" "stages"]))]
    (assert (= expected (source-stages fixture))
            (str "decoded source differs from preregistration: " (get fixture "id")))))
(let [malformed (first (filter #(= "N05" (get % "id")) (get manifest "fixtures")))]
  (assert malformed)
  (assert (try (parse-source malformed) false
               (catch MultipleCompilationErrorsException _ true))
          "malformed quoting unexpectedly parsed"))
(println (str (count supported)
              " fixture stage/script literals match Groovy CONVERSION AST; malformed quoting rejected. No Jenkins or product evidence."))
