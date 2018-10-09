## discourse-oauth2-blender-id

This plugin allows you to use Blender ID as authentication for
Discourse.

It is based on discourse-oauth2-basic, but it enforces some defaults and
supports Blender ID community badges.


## Usage

First, set up your Discourse application remotely on your OAuth2 provider.
It will require a **Redirect URI** which should be:

`http://DISCOURSE_HOST/auth/oauth2_blender_id/callback`

Replace `DISCOURSE_HOST` with the approriate value, and make sure you are
using `https` if enabled. The OAuth2 provider should supply you with a
client ID and secret, as well as a couple of URLs.

Visit your **Admin** > **Settings** > **Login** and fill in the basic
configuration for the OAuth2 provider:

* `oauth2_enabled` - check this off to enable the feature

* `oauth2_client_id` - the client ID from your provider

* `oauth2_client_secret` - the client secret from your provider


The plugin will also start a background job, which will run through the
existing OAuth credentials and try to fetch badges for the users.
The job will run every 30 minues.


### Issues

Please use [this page](https://github.com/fsiddi/discourse-oauth2-blender-id) to discuss
issues with the plugin, including bugs and feature reqests.


### License

MIT
