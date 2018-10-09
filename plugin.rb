# name: discourse-blender-id
# about: Blender ID OAuth Plugin
# version: 0.1
# authors: Francesco Siddi
# url: https://github.com/fsiddi/discourse-blender-id

require_dependency 'auth/oauth2_authenticator.rb'

enabled_site_setting :blender_id_enabled

module BlenderIdUtils
  extend self

  def log(info)
    Rails.logger.warn("Blender ID Debugging: #{info}") if SiteSetting.blender_id_debug_auth
  end

  def get_blender_id_badges
    # Get the existing badge names from Plugin Store
    badges = ::PluginStore.get("blender_id", "blender_id_badges")
    if not badges
      return Set.new()
    end
    return badges
  end

  def store_oauth_user_credentials(user_id, oauth_user_id, credentials)
    to_store = {user_id: user_id, oauth_user_id: oauth_user_id.to_s}
    unless credentials.nil?
      to_store['credentials'] = credentials.to_hash
    end
    ::PluginStore.set("blender_id", "blender_id_user_#{oauth_user_id}", to_store)
  end

  def badge_grant
    log("Granting badges")
    # Find all PluginStore rows related to the current plugin
    # TODO(fsiddi): improve this query, buy filtering out values that do not include 'credentials' in the JSON
    rows = PluginStoreRow.where('plugin_name = ? AND key LIKE ?', 'blender_id', 'blender_id_user_%').to_a
    rows.each do |row|
      ps_row = PluginStore.cast_value(row.type_name, row.value)
      # Skip if credentials are not found (see todo above for a possible improvement)
      next if not ps_row.key?("credentials")
      begin
        # Try to fetch user badges and handle possible failures. In particular, if the response status is 403,
        # revoke the user OAuth credentials to prevent further queries in the future.
        user_badges = fetch_user_badges(ps_row['credentials']['token'], ps_row['oauth_user_id'])
      rescue OpenURI::HTTPError => error
        response = error.io
        Rails.logger.warn("Error fetching badges for user #{ps_row['oauth_user_id']}: #{response.status}")
        if response.status[0] == '403'
          # Revoke credential is user is not authorized
          Rails.logger.warn("Removing expired or invalid credentials for user #{ps_row['oauth_user_id']}")
          store_oauth_user_credentials(ps_row['user_id'], ps_row['oauth_user_id'], nil)
        end
        return
      end
    
      user = User.where(id: ps_row['user_id']).first
      log("Updating badges for User: #{user.id}")
      update_user_badges(user_badges, user)
    end
  end

  def query_api_endpoint(token, endpoint)
    # Fetch JSON info from an api endpoint (this is the place where we talk to Blender ID)
    api_url = "#{SiteSetting.blender_id_url}api/#{endpoint}"
    log("api_url: GET #{api_url}")
    bearer_token = "Bearer #{token}"
    json_response = open(api_url, 'Authorization' => bearer_token).read
    return JSON.parse(json_response)
  end

  def fetch_user_badges(token, id)
    user_badges_json = query_api_endpoint(token, "badges/#{id}")
    log("user_badges_json: #{user_badges_json['badges']}")
    return user_badges_json['badges']
  end

  def update_user_badges(badges, user)
    # Add or remove Blender ID badges
    
    badge_names_incoming = Set.new()
    badges.each do |key, value|
      log("Processing badge: #{key}")
      # Make sure the badge exists in Discourse
      # TODO(fsiddi): Update the badge if something changed (e.g. image or description)
      unless b = Badge.find_by(name: value['label'])
        image = value.has_key?('image') ? value['image'] : nil
        b = Badge.create!(name: value['label'],
          description: value['label'],
          image: image,
          badge_type_id: 1)
      end
      # Assign the badge (ignoring if the user already has it)
      BadgeGranter.grant(b, user)
      # Add to list for comparing with badge_names_all later
      badge_names_incoming << value['label']
    end

    badge_names_all = get_blender_id_badges

    # Combine all the exsiting badges with the incoming one
    # This is meant to automatically extend the list of existing badges
    badge_names_all_updated = badge_names_all + badge_names_incoming
    ::PluginStore.set("blender_id", "blender_id_badges", badge_names_all_updated)

    # Find and remove old badges
    to_remove_badges = badge_names_all_updated - badge_names_incoming
    to_remove_badges.each { |badge_name|
      b = Badge.find_by(name: badge_name)
      if b
        ub = UserBadge.find_by(badge_id: b.id, user_id: user.id)
        if ub
          BadgeGranter.revoke(ub)
        end
      end
    }
  end

end

class ::OmniAuth::Strategies::BlenderId < ::OmniAuth::Strategies::OAuth2
  option :name, "blender_id"
  info do
    {
      id: access_token['id']
    }
  end

  def callback_url
    Discourse.base_url_no_prefix + script_name + callback_path
  end
end

class BlenderIdAuthenticator < ::Auth::OAuth2Authenticator
  include BlenderIdUtils

  def register_middleware(omniauth)
    omniauth.provider :blender_id,
                      name: 'blender_id',
                      setup: lambda { |env|
                        opts = env['omniauth.strategy'].options
                        opts[:client_id] = SiteSetting.blender_id_client_id
                        opts[:client_secret] = SiteSetting.blender_id_client_secret
                        opts[:provider_ignores_state] = false
                        opts[:client_options] = {
                          authorize_url: "#{SiteSetting.blender_id_url}oauth/authorize",
                          token_url: "#{SiteSetting.blender_id_url}oauth/token",
                          token_method: 'post'.to_sym
                        }
                        opts[:authorize_options] = SiteSetting.blender_id_authorize_options.split("|").map(&:to_sym)
                        opts[:token_params] = { headers: { 'Authorization' => basic_auth_header } }

                        unless SiteSetting.blender_id_scope.blank?
                          opts[:scope] = SiteSetting.blender_id_scope
                        end
                      }
  end

  def basic_auth_header
    "Basic " + Base64.strict_encode64("#{SiteSetting.blender_id_client_id}:#{SiteSetting.blender_id_client_secret}")
  end

  def walk_path(fragment, segments)
    first_seg = segments[0]
    return if first_seg.blank? || fragment.blank?
    return nil unless fragment.is_a?(Hash) || fragment.is_a?(Array)
    if fragment.is_a?(Hash)
      deref = fragment[first_seg] || fragment[first_seg.to_sym]
    else
      deref = fragment[0] # Take just the first array for now, maybe later we can teach it to walk the array if we need to
    end

    return (deref.blank? || segments.size == 1) ? deref : walk_path(deref, segments[1..-1])
  end

  def json_walk(result, user_json, prop)
    path = SiteSetting.send("oauth2_json_#{prop}_path")
    if path.present?
      segments = path.split('.')
      val = walk_path(user_json, segments)
      result[prop] = val if val.present?
    end
  end

  def fetch_user_details(token)
    user_json = query_api_endpoint(token, "me")

    log("user_json: #{user_json}")

    result = {}
    if user_json.present?
      json_walk(result, user_json, :user_id)
      json_walk(result, user_json, :username)
      json_walk(result, user_json, :name)
      json_walk(result, user_json, :email)
      json_walk(result, user_json, :avatar)
    end

    result
  end

  def after_authenticate(auth)
    log("after_authenticate response: \n\ncreds: #{auth['credentials'].to_hash}\ninfo: #{auth['info'].to_hash}\nextra: #{auth['extra'].to_hash}")

    result = Auth::Result.new
    token = auth['credentials']['token']
    user_details = fetch_user_details(token)

    result.name = user_details[:name]
    result.username = user_details[:username]
    result.email = user_details[:email]
    result.email_valid = result.email.present?
    avatar_url = user_details[:avatar]

    # Look for Oauth user info in Plugin Store
    current_info = ::PluginStore.get("blender_id", "blender_id_user_#{user_details[:user_id]}")
    if current_info
      result.user = User.where(id: current_info[:user_id]).first
    else
      # Look for OAuth user info in the Plugin Store for the (previously used) basic_oauth2 plugin
      legacy_info = ::PluginStore.get("oauth2_basic", "oauth2_basic_user_#{user_details[:user_id]}")
      if legacy_info
        result.user = User.where(id: legacy_info[:user_id]).first
      else
        # Look for existing user
        result.user = User.find_by_email(result.email)
      end
    end

    if result.user && user_details[:user_id]
      # Update OAuth credentials
      store_oauth_user_credentials(result.user.id, user_details[:user_id], auth['credentials'])
      # Update user badges
      badges = fetch_user_badges(token, user_details[:user_id])
      update_user_badges(badges, result.user)
    end

    Jobs.enqueue(:download_avatar_from_url,
      url: avatar_url,
      user_id: result.user.id,
      override_gravatar: SiteSetting.sso_overrides_avatar
    ) if result.user && avatar_url.present?

    result.extra_data = { blender_id_user_id: user_details[:user_id] }
    result
  end

  def after_create_account(user, auth)
    store_oauth_user_credentials(user.id, auth[:extra_data][:blender_id_user_id], auth['credentials'])
  end

  def enabled?
    SiteSetting.blender_id_enabled
  end
end

after_initialize do
  class ::BlenderIdBadgesUpdateJob < Jobs::Scheduled
    every 30.minutes
    def execute(args)
      BlenderIdUtils.badge_grant
    end
  end
end

auth_provider title_setting: "blender_id_button_title",
              enabled_setting: "blender_id_enabled",
              authenticator: BlenderIdAuthenticator.new('blender_id'),
              message: "Blender ID",
              full_screen_login_setting: "blender_id_full_screen_login"


register_css <<CSS

  button.btn-social.blender_id {
    background-color: #6d6d6d;
  }

CSS
