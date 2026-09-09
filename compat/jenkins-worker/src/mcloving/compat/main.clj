(ns mcloving.compat.main
  "Deny-authority entry point for the isolated Jenkins compiler worker."
  (:require [mcloving.compat.profile :as profile]
            [mcloving.compat.protocol :as protocol]
            [mcloving.compat.sequential-protocol :as sequential])
  (:gen-class))

(defn -main
  [& _args]
  (let [response
        (try
          (let [target-profile (profile/load-and-verify!)
                {:keys [request bytes]} (protocol/read-request-with-bytes! System/in)]
            (if (= sequential/protocol-version (:protocol request))
              (sequential/handle-request target-profile request bytes)
              (protocol/handle-request target-profile request)))
          (catch Throwable throwable
            (protocol/rejection throwable)))]
    (println (protocol/canonical-edn response))
    (flush)))
