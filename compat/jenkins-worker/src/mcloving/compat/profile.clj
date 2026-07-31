(ns mcloving.compat.profile
  "Exact runtime-profile verification. No profile field grants execution authority."
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import (java.io FileInputStream)
           (java.nio.charset StandardCharsets)
           (java.nio.file Files LinkOption Path Paths)
           (java.security MessageDigest)
           (java.util Properties)))

(def profile-path "/opt/mcloving/profile/profile-v1.properties")
(def plugin-manifest-path "/opt/mcloving/profile/PLUGIN_SHA256SUMS")
(def plugin-root "/opt/mcloving/profile/plugins")
(def groovy-jar-path "/opt/mcloving/lib/groovy-all-2.4.21.jar")
(def jenkins-core-jar-path "/opt/mcloving/lib/jenkins-core-2.568.1.jar")

(defn sha256-bytes
  [bytes]
  (let [digest (.digest (MessageDigest/getInstance "SHA-256") bytes)]
    (apply str (map #(format "%02x" (bit-and % 0xff)) digest))))

(defn sha256-file
  [path]
  (with-open [input (io/input-stream path)]
    (let [digest (MessageDigest/getInstance "SHA-256")
          buffer (byte-array 65536)]
      (loop []
        (let [read-count (.read input buffer)]
          (when (pos? read-count)
            (.update digest buffer 0 read-count)
            (recur))))
      (apply str (map #(format "%02x" (bit-and % 0xff)) (.digest digest))))))

(defn- regular-file-no-links?
  [path]
  (let [candidate (Paths/get path (make-array String 0))]
    (and (Files/isRegularFile candidate (into-array LinkOption [LinkOption/NOFOLLOW_LINKS]))
         (not (Files/isSymbolicLink candidate)))))

(defn- read-properties
  [path]
  (let [properties (Properties.)]
    (with-open [input (FileInputStream. path)]
      (.load properties input))
    (into (sorted-map)
          (map (fn [[key value]] [(str key) (str value)]))
          properties)))

(defn- fail!
  [code]
  (throw (ex-info "worker profile verification failed" {:code code})))

(defn- require-property!
  [properties key expected]
  (when-not (= expected (get properties key))
    (fail! "E_PROFILE_MISMATCH")))

(defn- groovy-version
  []
  (let [groovy-system (Class/forName "groovy.lang.GroovySystem")
        method (.getMethod groovy-system "getVersion" (make-array Class 0))]
    (.invoke method nil (object-array 0))))

(defn- parse-manifest-line
  [line]
  (when-let [[_ digest relative]
             (re-matches #"([0-9a-f]{64})  (plugins/[A-Za-z0-9_.+-]+\.jpi)" line)]
    [digest relative]))

(defn- verify-plugins!
  [properties]
  (when-not (regular-file-no-links? plugin-manifest-path)
    (fail! "E_PROFILE_PLUGIN_MANIFEST"))
  (let [manifest-bytes (Files/readAllBytes (Paths/get plugin-manifest-path
                                                       (make-array String 0)))
        manifest-text (String. manifest-bytes StandardCharsets/UTF_8)
        lines (remove str/blank? (str/split-lines manifest-text))
        entries (mapv parse-manifest-line lines)]
    (when (or (some nil? entries)
              (not= (count entries)
                    (Long/parseLong (get properties "plugin.file.count" "-1"))))
      (fail! "E_PROFILE_PLUGIN_MANIFEST"))
    (when-not (= (sha256-bytes manifest-bytes)
                 (get properties "plugin.manifest.sha256"))
      (fail! "E_PROFILE_PLUGIN_MANIFEST"))
    (doseq [[expected relative] entries]
      (let [leaf (subs relative (count "plugins/"))
            path (str plugin-root "/" leaf)]
        (when (or (not (regular-file-no-links? path))
                  (not= expected (sha256-file path)))
          (fail! "E_PROFILE_PLUGIN_CONTENT"))))
    (count entries)))

(defn load-and-verify!
  []
  (when-not (regular-file-no-links? profile-path)
    (fail! "E_PROFILE_MISSING"))
  (let [properties (read-properties profile-path)
        java-runtime (System/getProperty "java.runtime.version")
        java-vendor (System/getProperty "java.vendor")
        groovy-version (groovy-version)]
    (require-property! properties "profile.version" "1")
    (require-property! properties "java.runtime.version" java-runtime)
    (require-property! properties "java.vendor" java-vendor)
    (require-property! properties "groovy.version" groovy-version)
    (when (or (not= (get properties "groovy.jar.sha256")
                    (sha256-file groovy-jar-path))
              (not= (get properties "jenkins.core.jar.sha256")
                    (sha256-file jenkins-core-jar-path)))
      (fail! "E_PROFILE_RUNTIME_CONTENT"))
    (let [plugin-count (verify-plugins! properties)]
      (sorted-map
       :controller (get properties "source.controller")
       :groovy-version groovy-version
       :java-runtime java-runtime
       :jenkins-core-version (get properties "jenkins.core.version")
       :plugin-count plugin-count
       :profile-id (get properties "profile.id")
       :profile-sha256 (sha256-file profile-path)
       :snapshot-fingerprint (get properties "source.snapshot.fingerprint")))))
