(ns mcloving.compat.protocol-test
  (:require [clojure.test :refer [deftest is testing]]
            [mcloving.compat.protocol :as protocol])
  (:import (java.io ByteArrayInputStream)))

(def profile
  (sorted-map
   :controller "mario/jenkins-oracle-228"
   :profile-id "mario-jenkins-oracle-228"
   :profile-sha256 (apply str (repeat 64 "a"))))

(defn request-stream
  [value]
  (ByteArrayInputStream. (.getBytes value "UTF-8")))

(deftest probe-is-deterministic-and-denies-authority
  (with-redefs [protocol/current-environment-keys (fn [] #{"LANG" "TZ"})]
    (let [request (protocol/read-request!
                   (request-stream
                    (str "{:operation :probe"
                         " :protocol \"mcloving.jenkins.compiler/1\""
                         " :request-id \"unit-probe\""
                         " :target-profile-sha256 \""
                         (:profile-sha256 profile)
                         "\"}")))
          first-result (protocol/handle-request profile request)
          second-result (protocol/handle-request profile request)]
      (is (= first-result second-result))
      (is (= :ok (:status first-result)))
      (is (every? false? (vals (:authority first-result))))
      (is (= (protocol/canonical-edn first-result)
             (protocol/canonical-edn second-result))))))

(deftest malformed-and-oversize-input-fail-closed
  (testing "malformed EDN"
    (is (= "E_REQUEST_INVALID"
           (try
             (protocol/read-request! (request-stream "{"))
             nil
             (catch clojure.lang.ExceptionInfo exception
               (:code (ex-data exception)))))))
  (testing "oversize input"
    (is (= "E_REQUEST_TOO_LARGE"
           (try
             (protocol/read-request!
              (request-stream (apply str (repeat (inc protocol/max-request-bytes) "x"))))
             nil
             (catch clojure.lang.ExceptionInfo exception
               (:code (ex-data exception)))))))
  (testing "a valid prefix cannot hide a trailing form"
    (is (= "E_REQUEST_TRAILING"
           (try
             (protocol/read-request! (request-stream "{} {:operation :probe}"))
             nil
             (catch clojure.lang.ExceptionInfo exception
               (:code (ex-data exception))))))))

(deftest unknown-fields-and-profile-substitution-are-rejected
  (with-redefs [protocol/current-environment-keys (fn [] #{"LANG" "TZ"})]
    (let [base {:operation :probe
                :protocol protocol/protocol-version
                :request-id "unit-substitution"
                :target-profile-sha256 (:profile-sha256 profile)}]
      (is (= "E_REQUEST_FIELDS"
             (try
               (protocol/handle-request profile (assoc base :surprise true))
               nil
               (catch clojure.lang.ExceptionInfo exception
                 (:code (ex-data exception))))))
      (is (= "E_TARGET_PROFILE"
             (try
               (protocol/handle-request
                profile
                (assoc base :target-profile-sha256 (apply str (repeat 64 "b"))))
               nil
               (catch clojure.lang.ExceptionInfo exception
                 (:code (ex-data exception)))))))))
