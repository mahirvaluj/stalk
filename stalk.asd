(defsystem "stalk"
  :depends-on (#:ironclad #:usocket #:spack #:alexandria #:bordeaux-threads #:cl-leb128)
  :components ((:file "package")
               (:file "identity")
               (:file "stalk")))
