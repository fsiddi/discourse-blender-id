# name: discourse-oauth2-blender-id
# about: Blender ID OAuth Plugin
# version: 0.1
# authors: Francesco Siddi
# url: https://github.com/fsiddi/discourse-oauth2-blender-id

require_dependency 'auth/oauth2_authenticator.rb'

enabled_site_setting :oauth2_blender_id_enabled

module OAuth2BlenderIdUtils
  extend self
  def log(info)
    Rails.logger.warn("Blender ID OAuth2 Debugging: #{info}") if SiteSetting.oauth2_blender_id_debug_auth
  end

  def badge_grant
    log("Granting badges")
    rows = PluginStoreRow.where('plugin_name = ? AND key LIKE ?', 'oauth2_blender_id', 'oauth2_blender_id_user_%').to_a
    # ps = Hash[rows.map { |row| [row.key, PluginStore.cast_value(row.type_name, row.value)] }]
    # ps = PluginStore.get('oauth2_blender_id','oauth2_blender_id_user_2338')
    # log("Friend: #{ps}")
    rows.each do |row|
      ps_row = PluginStore.cast_value(row.type_name, row.value)
      user_badges = fetch_user_badges(ps_row['credentials']['token'], ps_row['oauth_user_id'])
      user = User.where(id: ps_row['user_id']).first
      log("Updating badges for: #{user.id}")
      update_user_badges(user_badges, user)
    end
  end

  def query_api_endpoint(token, endpoint)
    api_url = "#{SiteSetting.oauth2_blender_id_url}api/#{endpoint}"
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
    all_badges = get_blender_id_badges
    incoming_badges = Array.new()
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
      # Add to list for comparing with all_badges later
      incoming_badges << value['label']
    end

    # Find and remove old badges (all_badges - incoming_badges)
    to_remove_badges = all_badges - incoming_badges
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

class ::OmniAuth::Strategies::Oauth2BlenderId < ::OmniAuth::Strategies::OAuth2
  option :name, "oauth2_blender_id"
  info do
    {
      id: access_token['id']
    }
  end

  def callback_url
    Discourse.base_url_no_prefix + script_name + callback_path
  end
end

class OAuth2BlenderIdAuthenticator < ::Auth::OAuth2Authenticator
  include OAuth2BlenderIdUtils

  def register_middleware(omniauth)
    omniauth.provider :oauth2_blender_id,
                      name: 'oauth2_blender_id',
                      setup: lambda { |env|
                        opts = env['omniauth.strategy'].options
                        opts[:client_id] = SiteSetting.oauth2_blender_id_client_id
                        opts[:client_secret] = SiteSetting.oauth2_blender_id_client_secret
                        opts[:provider_ignores_state] = false
                        opts[:client_options] = {
                          authorize_url: "#{SiteSetting.oauth2_blender_id_url}oauth/authorize",
                          token_url: "#{SiteSetting.oauth2_blender_id_url}oauth/token",
                          token_method: 'post'.to_sym
                        }
                        opts[:authorize_options] = SiteSetting.oauth2_blender_id_authorize_options.split("|").map(&:to_sym)
                        opts[:token_params] = { headers: { 'Authorization' => basic_auth_header } }

                        unless SiteSetting.oauth2_blender_id_scope.blank?
                          opts[:scope] = SiteSetting.oauth2_blender_id_scope
                        end
                      }
  end

  def basic_auth_header
    "Basic " + Base64.strict_encode64("#{SiteSetting.oauth2_blender_id_client_id}:#{SiteSetting.oauth2_blender_id_client_secret}")
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

  def get_blender_id_badges
    # TODO(fsiddi): Turn this into a Blender ID query
    return ['Blender Network Member', 'Blender Cloud Subscriber']
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

  def store_oauth_user_credentials(user_id, oauth_user_id, credentials)
    ::PluginStore.set("oauth2_blender_id", "oauth2_blender_id_user_#{oauth_user_id}", {
      user_id: user_id, oauth_user_id: oauth_user_id.to_s, credentials: credentials.to_hash})
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

    current_info = ::PluginStore.get("oauth2_blender_id", "oauth2_blender_id_user_#{user_details[:user_id]}")
    if current_info
      result.user = User.where(id: current_info[:user_id]).first
      # Update OAuth credentials
      store_oauth_user_credentials(result.user.id, user_details[:user_id], auth['credentials'])
      # Update user badges
      badges = fetch_user_badges(token, user_details[:user_id])
      update_user_badges(badges, result.user)
    else
      # Look for existing user
      result.user = User.find_by_email(result.email)
      if result.user && user_details[:user_id]
        store_oauth_user_credentials(result.user.id, user_details[:user_id], auth['credentials'])
        # Update user badges
        badges = fetch_user_badges(token, user_details[:user_id])
        update_user_badges(badges, result.user)
      end
    end

    Jobs.enqueue(:download_avatar_from_url,
      url: avatar_url,
      user_id: result.user.id,
      override_gravatar: SiteSetting.sso_overrides_avatar
    ) if result.user && avatar_url.present?

    result.extra_data = { oauth2_blender_id_user_id: user_details[:user_id] }
    result
  end

  def after_create_account(user, auth)
    store_oauth_user_credentials(user.id, auth[:extra_data][:oauth2_blender_id_user_id], auth['credentials'])
  end

  def enabled?
    SiteSetting.oauth2_blender_id_enabled
  end
end

after_initialize do
  class ::BlenderIdBadgesUpdateJob < Jobs::Scheduled
    every 2.minutes
    def execute(args)
      OAuth2BlenderIdUtils.badge_grant
    end
  end
end

auth_provider title_setting: "oauth2_button_title",
              enabled_setting: "oauth2_enabled",
              authenticator: OAuth2BlenderIdAuthenticator.new('oauth2_blender_id'),
              message: "OAuth2",
              full_screen_login_setting: "oauth2_full_screen_login"


register_css <<CSS

  button.btn-social.oauth2_blender_id {
    background-color: #6d6d6d;
  }

CSS
