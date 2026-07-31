(ns mcloving.compat.compiler-test
  (:require [clojure.test :refer [deftest is testing]]
            [mcloving.compat.compiler :as compiler]))

(def admitted-source
  "#!/usr/bin/env groovy\n\npipeline {\n    agent any\n    stages {\n        stage('Build') {\n            steps {\n                sh 'echo \"Hello World\"'\n            }\n        }\n    }\n}")

(def profile
  (sorted-map
   :controller "mario/jenkins-oracle-228"
   :profile-sha256 (apply str (repeat 64 "a"))
   :snapshot-fingerprint compiler/admitted-inventory-fingerprint))

(def request
  {:inventory-fingerprint compiler/admitted-inventory-fingerprint
   :job-actor compiler/admitted-actor
   :job-effective-time compiler/admitted-effective-time
   :job-enabled false
   :job-generation compiler/admitted-job-generation
   :job-id compiler/admitted-job-id
   :job-reason compiler/admitted-reason
   :source-sha256 compiler/admitted-source-sha256})

(deftest exact-oracle-case-compiles-deterministically
  (let [first (compiler/compile-admitted! "compiler/1" profile request admitted-source)
        second (compiler/compile-admitted! "compiler/1" profile request admitted-source)]
    (is (= first second))
    (is (= {:stages 1 :steps 1} (:semantic first)))
    (is (= {:effect-authority false
            :jenkins-selector "any"
            :mcloving-platform "any"
            :trust-pool "migration-deny-authority"}
           (:agent-mapping first)))
    (is (.contains (:pipeline-yaml first) "program: \"/bin/sh\""))
    (is (.contains (:pipeline-yaml first)
                   "args: [\"-xe\", \"-c\", \"echo \\\"Hello World\\\"\"]"))
    (is (.contains (:jobstate-yaml first) "state: disabled"))
    (is (= 64 (count (:pipeline-yaml-sha256 first))))
    (is (= 64 (count (:jobstate-yaml-sha256 first))))))

(deftest structural-and-provenance-expansion-fail-closed
  (testing "source mutation is not silently admitted"
    (is (= "E_SOURCE_NOT_ADMITTED"
           (try
             (compiler/compile-admitted!
              "compiler/1"
              profile
              (assoc request :source-sha256 (apply str (repeat 64 "b")))
              admitted-source)
             nil
             (catch clojure.lang.ExceptionInfo exception
               (:code (ex-data exception)))))))
  (testing "a dynamic shell expression is outside the subset"
    (is (= "E_STEP_DYNAMIC"
           (try
             (compiler/compile-admitted!
              "compiler/1"
              profile
              request
              (str "pipeline { agent any; stages { stage('Build') { "
                   "steps { sh \"echo ${env.HOME}\" } } } }"))
             nil
             (catch clojure.lang.ExceptionInfo exception
               (:code (ex-data exception))))))))
