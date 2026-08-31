(ns mcloving.compat.test-runner
  (:require [clojure.test :as test]
            [mcloving.compat.compiler-test]
            [mcloving.compat.protocol-test]))

(defn -main
  [& _args]
  (let [result (test/run-tests 'mcloving.compat.compiler-test
                               'mcloving.compat.protocol-test)
        expected-tests 6
        failures (+ (:fail result) (:error result))]
    (shutdown-agents)
    ;; clojure.test exits successfully when a namespace or every deftest is
    ;; accidentally removed. This is a closed compatibility denominator, so a
    ;; partial or zero-test run is a failed gate even when nothing reports red.
    (when (or (pos? failures) (not= expected-tests (:test result)))
      (binding [*out* *err*]
        (println "compatibility test population mismatch: expected"
                 expected-tests "executed" (:test result)
                 "failures" failures))
      (System/exit 1))))
