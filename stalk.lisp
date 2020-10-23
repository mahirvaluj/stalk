(in-package :stalk)

;; (ql:quickload '(:ironclad :usocket :spack :alexandria :bordeaux-threads :cl-leb128))

(defparameter *default-identity-location* `(,"~/.stalk/id_pub" 
                                             ,"~/.stalk/id_priv"))
(defvar *default-identity* (load-identity-from-files (car *default-identity-location*) (cadr *default-identity-location*)))

(defvar *id*)
(defvar *port* 6434)
(defvar *codes*
  `((400 :bad-request) (401 :bad-handshake) (500 :crash)))
(defun get-stat-code (keyword)
  (car (find-if #'(lambda (i) (eql keyword (cadr i))) *codes*)))
(defun get-keyword (stat-code)
  (cadr (find-if #'(lambda (i) (eql stat-code (car i))) *codes*)))

(defclass stalk-connection()
  ((host
    :accessor host
    :initarg :host)
   (port
    :accessor port
    :initarg :port)
   (peer-identity
    :accessor peer-identity
    :initarg :peer-identity)
   (identity
    :accessor identity
    :initarg :identity)
   (socket
    :reader socket
    :initarg :socket)
   (spack-handler
    :reader spack-handler
    :initarg :spack-handler)
   (cryptosystem
    :accessor cryptosystem
    :initarg :cryptosystem)))


(defmethod register-spack-handler ((conn stalk-connection) (f function))
  )

(defun make-connection (sock peer-identity cryptosystem identity)
  (make-instance 'stalk-connection
                 :host (usocket:get-peer-address sock)
                 :port (usocket:get-peer-port sock)
                 :peer-identity peer-identity
                 :identity identity
                 :cryptosystem cryptosystem
                 :socket sock))

(defun listener (host port connection-handler &key (identity *default-identity*))
  (loop do 
       (let ((socket (usocket:socket-listen host port)))
         (usocket:wait-for-input socket)
         (bt:make-thread
          #'(lambda ()
              (multiple-value-bind (peer-identity cryptosystem)
                  (unwind-protect
                       (handshake (usocket:socket-accept socket))
                    (progn (send-error socket :bad-handshake) (return nil)))
                (when peer-identity
                  (funcall connection-handler
                           (make-connection socket peer-identity cryptosystem identity)))))))))

(defun handshake (sock)
  (let ((state nil) (curr))
    (unless (setf curr (spack:parse sock))
      (error "connection error"))
    (cond ((unencrypted-hello curr)
           ())
          ((encrypted-hello curr)
           ())
          (t (error "bad hello")))))

(defun send-error (sock error-keyword)
  (let ((sp (make-instance 'spack)))
    (spush (get-stat-code error-keyword))
    (loop for i across (spack:out sp) do
         (write-byte i sock))
    (force-output sock)
    (usocket:socket-close sock)))

(defun connect (host port &optional identity &key handler))

(defun send (spack connection))

(defun flush (connection))

