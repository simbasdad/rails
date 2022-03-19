# frozen_string_literal: true

module ActionDispatch
  module Session
    class CsrfTokenInCookieStore < CookieStore
      def initialize(app, options = nil)
        options[:same_site] = :lax
        @store = create_store(app, options)
        super
      end

      def load_session(req)
        cookie_sid, cookie_data = super
        store_sid, store_data = @store.find_session(req, cookie_sid)

        if (cookie_data["_empty"] && store_data.empty?) || cookie_sid.public_id == store_sid.public_id
          store_data["_csrf_token"] = cookie_data["_csrf_token"]
        end

        # If the cookie doesn't contain "_empty", then this is a new session and shouldn't have a CSRF token.

        # If cookie is for empty session and store is not empty; or
        # If cookie is for non-empty session and session IDs dont match; then
        # CSRF token is, so don't set it.

        [cookie_sid, store_data]
      end

      def write_session(req, sid, session, options)
        csrf_token = session.delete("_csrf_token")
        cookie_value = {
          "session_id" => sid.public_id,
          "_csrf_token" => csrf_token,
          "_empty" => session.empty?
        }.compact

        if session.empty?
          @store.delete_session(req, sid, options)
        else
          @store.write_session(req, sid, session, options)
        end

        super(req, sid, cookie_value, options)
      end

      def delete_session(req, sid, options)
        @store.delete_session(req, sid, options)
        super
      end

      private

      def create_store(app, options)
        store = options[:store] || :cache_store
        case store
        when Symbol
          ActionDispatch::Session.const_get(name.to_s.camelize).new(app, options)
        when Class
          store.new(app, options)
        else
          raise ArgumentError "Please specify a symbol or class for the :store option of the CsrfTokenInCookieStore"
        end
      end
    end
  end
end
