(ns mcloving.compat.protocol
  "Versioned, bounded worker protocol. It is intentionally compile-only and deny-authority."
  (:require [clojure.edn :as edn]
            [clojure.string :as str]
            [mcloving.compat.compiler :as compiler]
            [mcloving.compat.profile :as profile])
  (:import (java.io ByteArrayOutputStream InputStream PushbackReader StringReader)
           (java.nio.file Files LinkOption Paths StandardOpenOption)))

(def protocol-version "mcloving.jenkins.compiler/1")
(def compiler-id "mcloving-jenkins-compiler-worker/1")
(def max-request-bytes 262144)
(def max-source-bytes 262144)

(def authority
  (sorted-map
   :agent-protocol false
   :controller-filesystem false
   :controller-store false
   :credentials false
   :effects false
   :network false
   :scheduler false
   :workload-execution false))

(def allowed-environment
  #{"HOME" "HOSTNAME" "LANG" "PATH" "TZ"})

(def forbidden-environment-pattern
  #"(?i)(agent|aws|controller|credential|database|github|jenkins_home|key|password|postgres|scheduler|secret|token)")

(defn canonicalize
  [value]
  (cond
    (map? value) (into (sorted-map)
                       (map (fn [[key nested]] [key (canonicalize nested)]))
                       value)
    (vector? value) (mapv canonicalize value)
    (sequential? value) (mapv canonicalize value)
    :else value))

(defn canonical-edn
  [value]
  (pr-str (canonicalize value)))

(defn- fail!
  [code]
  (throw (ex-info "worker request rejected" {:code code})))

(defn read-request!
  [^InputStream input]
  (let [output (ByteArrayOutputStream.)
        buffer (byte-array 8192)]
    (loop [total 0]
      (let [read-count (.read input buffer)]
        (if (neg? read-count)
          (let [bytes (.toByteArray output)]
            (when (zero? (alength bytes))
              (fail! "E_REQUEST_EMPTY"))
            (try
              (with-open [reader
                          (PushbackReader.
                           (StringReader.
                            (String. bytes java.nio.charset.StandardCharsets/UTF_8)))]
                (let [options
                      {:eof ::eof
                       :readers {}
                       :default (fn [_tag _value] (fail! "E_REQUEST_TAGGED"))}
                      request (edn/read options reader)
                      trailing (edn/read options reader)]
                  (when (= ::eof request)
                    (fail! "E_REQUEST_EMPTY"))
                  (when-not (= ::eof trailing)
                    (fail! "E_REQUEST_TRAILING"))
                  request))
              (catch clojure.lang.ExceptionInfo exception
                (throw exception))
              (catch Throwable _
                (fail! "E_REQUEST_INVALID"))))
          (let [next-total (+ total read-count)]
            (when (> next-total max-request-bytes)
              (fail! "E_REQUEST_TOO_LARGE"))
            (.write output buffer 0 read-count)
            (recur next-total)))))))

(defn- exact-keys!
  [request expected]
  (when-not (= expected (set (keys request)))
    (fail! "E_REQUEST_FIELDS")))

(defn- valid-sha?
  [value]
  (and (string? value) (boolean (re-matches #"[0-9a-f]{64}" value))))

(defn- valid-request-id?
  [value]
  (and (string? value)
       (<= 1 (count value) 96)
       (boolean (re-matches #"[A-Za-z0-9][A-Za-z0-9._:-]*" value))))

(defn- valid-job-id?
  [value]
  (and (string? value)
       (<= 1 (count value) 128)
       (boolean (re-matches #"[A-Za-z0-9][A-Za-z0-9._-]*" value))))

(defn current-environment-keys
  []
  (set (keys (System/getenv))))

(defn- environment-safe!
  []
  (let [keys (current-environment-keys)]
    (when (or (some #(re-find forbidden-environment-pattern %) keys)
              (some #(not (contains? allowed-environment %)) keys))
      (fail! "E_ENV_AUTHORITY"))
    (sort keys)))

(defn- read-source-bytes!
  [path]
  (try
    (with-open [input
                (Files/newInputStream
                 path
                 (into-array
                  java.nio.file.OpenOption
                  [StandardOpenOption/READ LinkOption/NOFOLLOW_LINKS]))]
      (let [output (ByteArrayOutputStream.)
            buffer (byte-array 8192)]
        (loop [total 0]
          (let [read-count (.read input buffer)]
            (if (neg? read-count)
              (.toByteArray output)
              (let [next-total (+ total read-count)]
                (when (> next-total max-source-bytes)
                  (fail! "E_SOURCE_TOO_LARGE"))
                (.write output buffer 0 read-count)
                (recur next-total)))))))
    (catch java.io.IOException _
      (fail! "E_SOURCE_TYPE"))))

(defn- source-input!
  [request]
  (when-not (= "/input/Jenkinsfile" (:source-path request))
    (fail! "E_SOURCE_PATH"))
  (let [path (Paths/get (:source-path request) (make-array String 0))]
    (when (or (Files/isSymbolicLink path)
              (not (Files/isRegularFile
                    path
                    (into-array LinkOption [LinkOption/NOFOLLOW_LINKS]))))
      (fail! "E_SOURCE_TYPE"))
    (let [size (Files/size path)]
      (when (> size max-source-bytes)
        (fail! "E_SOURCE_TOO_LARGE"))
      (let [bytes (read-source-bytes! path)
            actual (profile/sha256-bytes bytes)]
        (when-not (= actual (:source-sha256 request))
          (fail! "E_SOURCE_DIGEST"))
        {:receipt (sorted-map :bytes (alength bytes) :sha256 actual)
         :source (String. bytes java.nio.charset.StandardCharsets/UTF_8)}))))

(defn- base-response
  [profile request status]
  (sorted-map
   :authority authority
   :compiler compiler-id
   :profile profile
   :protocol protocol-version
   :request-id (:request-id request)
   :status status))

(defn handle-request
  [profile request]
  (when-not (map? request)
    (fail! "E_REQUEST_TYPE"))
  (when-not (= protocol-version (:protocol request))
    (fail! "E_PROTOCOL_VERSION"))
  (when-not (valid-request-id? (:request-id request))
    (fail! "E_REQUEST_ID"))
  (when-not (= (:target-profile-sha256 request) (:profile-sha256 profile))
    (fail! "E_TARGET_PROFILE"))
  (case (:operation request)
    :probe
    (do
      (exact-keys! request
                   #{:operation :protocol :request-id
                     :target-profile-sha256})
      (let [environment (environment-safe!)]
        (assoc (base-response profile request :ok)
               :environment-keys environment)))

    :compile
    (do
      (exact-keys! request
                   #{:inventory-fingerprint :job-actor :job-effective-time
                     :job-enabled :job-generation :job-id :job-reason
                     :operation :protocol :request-id :source-path
                     :source-sha256 :target-profile-sha256})
      (when-not (valid-sha? (:source-sha256 request))
        (fail! "E_SOURCE_DIGEST"))
      (when-not (and (valid-sha? (:job-generation request))
                     (valid-sha? (:inventory-fingerprint request))
                     (valid-job-id? (:job-id request))
                     (boolean? (:job-enabled request))
                     (string? (:job-reason request))
                     (string? (:job-actor request))
                     (string? (:job-effective-time request)))
        (fail! "E_JOB_PROVENANCE"))
      (environment-safe!)
      (let [{:keys [receipt source]} (source-input! request)]
        (try
          (assoc (base-response profile request :compiled)
                 :result (compiler/compile-admitted!
                          compiler-id profile request source)
                 :source receipt)
          (catch clojure.lang.ExceptionInfo exception
            (assoc (base-response profile request :unsupported)
                   :diagnostic
                   (sorted-map
                    :code (or (:code (ex-data exception))
                              "E_COMPILER_INTERNAL")
                    :message
                    "source is outside the currently admitted compiler subset")
                   :source receipt)))))

    (fail! "E_OPERATION")))

(defn rejection
  [throwable]
  (let [code (or (:code (ex-data throwable)) "E_WORKER_INTERNAL")]
    (sorted-map
     :authority authority
     :compiler compiler-id
     :diagnostic
     (sorted-map
      :code code
      :message "request rejected without execution authority")
     :protocol protocol-version
     :status :rejected)))
