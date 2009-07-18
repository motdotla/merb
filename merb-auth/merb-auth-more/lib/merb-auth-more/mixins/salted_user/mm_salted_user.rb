class Merb::Authentication
  module Mixins
    module SaltedUser
      module MMClassMethods
        def self.extended(base)
          base.class_eval do
            
            key :crypted_password,           String
            key :salt,                       String
            
            validates_presence_of   :password, :if => proc {|o| o.password_required? }
            
            before_save   :encrypt_password
          end # base.class_eval
          
        end # self.extended
        
        def authenticate(login, password)
          @u = find(:first, :conditions => {Merb::Authentication::Strategies::Basic::Base.login_param => login})
          @u && @u.authenticated?(password) ? @u : nil
        end
      end # MMClassMethods      
    end # SaltedUser
  end # Mixins
end # Merb::Authentication
