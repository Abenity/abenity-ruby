require "abenity_ruby"

ApiClient = AbenityRuby::ApiClient.new(
  "api_username",
  "api_password",
  "api_key"
)

results = ApiClient.reactivate_member('client_user_id');

if results['status'] == 'ok'
  puts "Success!"
else
  puts "There were some errors: \n"
  results['error'].each do |key, value|
    puts "#{key}: #{value} \n"
  end
end
