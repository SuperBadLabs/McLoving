(ns mcloving.compat.test-runner
  (:require [clojure.test :as test]
            [mcloving.compat.compiler-test]
            [mcloving.compat.protocol-test]))

(defn -main
  [& _args]
  (let [result (test/run-tests 'mcloving.compat.compiler-test
                               'mcloving.compat.protocol-test)
        failures (+ (:fail result) (:error result))]
    (shutdown-agents)
    (when (pos? failures)
      (System/exit 1))))
