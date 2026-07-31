(ns mcloving.compat.main
  "Deny-authority entry point for the isolated Jenkins compiler worker."
  (:require [mcloving.compat.profile :as profile]
            [mcloving.compat.protocol :as protocol])
  (:gen-class))

(defn -main
  [& _args]
  (let [response
        (try
          (protocol/handle-request
           (profile/load-and-verify!)
           (protocol/read-request! System/in))
          (catch Throwable throwable
            (protocol/rejection throwable)))]
    (println (protocol/canonical-edn response))
    (flush)))
