(ns mcloving.compat.sequential-test-runner
  (:require [clojure.test :as test] [mcloving.compat.sequential-test]))
(defn -main [& _]
  (let [result (test/run-tests 'mcloving.compat.sequential-test)]
    (shutdown-agents)
    (when (or (not= 13 (:test result)) (pos? (+ (:fail result) (:error result))))
      (binding [*out* *err*] (println "sequential test population/failure gate:" result))
      (System/exit 1))))
