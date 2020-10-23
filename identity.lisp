(in-package :stalk)

(defclass stalk-identity ()
  ((pubkey
    :accessor pubkey
    :initarg :pubkey)
   (privkey
    :accessor privkey
    :initarg :privkey)
   (keysize
    :accessor keysize
    :initarg :keysize)))

(defun int-to-le-byte-vector (int)
  (let ((a (make-array (ceiling (/ (log int 2) 8)) :element-type '(unsigned-byte 8) :fill-pointer 0)))
    (loop while (not (= int 0)) do
         (vector-push (mod int 256) a)
         (setf int (ash int -8)))
    a))

(defun le-byte-vector-to-int (bv)
  (let ((i 0) (p 0))
    (loop for z across bv do
         (format nil "test")
         (setf i (+ i (ash z (* p 8)))
               p (+ p 1)))
    i))

(defun make-identity (&key (keysize 2048))
  (multiple-value-bind (privkey pubkey) (ironclad:generate-key-pair :rsa :num-bits keysize)
    (make-instance 'stalk-identity :pubkey pubkey :privkey privkey)))

(defun save-identity-to-files (identity pubkey-path privkey-path)
  (with-open-file (f pubkey-path :direction :output :element-type '(unsigned-byte 8) :if-exists :supersede)
    (destructuring-bind (_1 pubint _2 modulus) (ironclad:destructure-public-key (pubkey identity))
      (declare (ignore _1 _2))
      (let ((vec (int-to-le-byte-vector (keysize identity))))
        (loop for i across vec do (write-byte i f))
        (loop for i from 0 below (- 4 (length vec)) do (write-byte 0 f)))
      (loop for i across (int-to-le-byte-vector pubint) do (write-byte i f))
      (loop for i across (int-to-le-byte-vector modulus) do (write-byte i f))))
  (with-open-file (f privkey-path :direction :output :element-type '(unsigned-byte 8) :if-exists :supersede)
    (destructuring-bind (_1 privint _2 modulus) (ironclad:destructure-private-key (privkey identity))
      (declare (ignore _1 _2))
      (let ((vec (int-to-le-byte-vector (keysize identity))))
        (loop for i across vec do (write-byte i f))
        (loop for i from 0 below (- 4 (length vec)) do (write-byte 0 f)))
      (loop for i across (int-to-le-byte-vector privint) do (write-byte i f))
      (loop for i across (int-to-le-byte-vector modulus) do (write-byte i f)))))

(defun load-identity-from-files (pubkey-path privkey-path)
  (let ((pub-keyfile (alexandria:read-file-into-byte-vector pubkey-path))
        (priv-keyfile (alexandria:read-file-into-byte-vector privkey-path))
        (keysize) (pubkey) (privkey) (modulus))
    (setf keysize (/ (le-byte-vector-to-int (subseq pub-keyfile 0 4)) 8)
          pubkey  (le-byte-vector-to-int (subseq pub-keyfile 4 (+ 4 keysize)))
          modulus (le-byte-vector-to-int (subseq pub-keyfile (+ 4 keysize)))
          privkey (le-byte-vector-to-int (subseq priv-keyfile 4 (+ 4 keysize))))
    (make-instance 'stalk-identity
                   :keysize (* 8 keysize)
                   :pubkey (ironclad:make-public-key :rsa :e pubkey :n modulus)
                   :privkey (ironclad:make-private-key :rsa :d privkey :n modulus))))
