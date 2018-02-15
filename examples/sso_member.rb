require "abenity_ruby"
require "date"
require "time"

ApiClient = AbenityRuby::ApiClient.new(
  "api_username",
  "api_password",
  "api_key"
)

member_info = {
  "creation_time" => (DateTime.now).strftime('%FT%T%:z'),
  "salt" => rand(0..100000),
  "send_welcome_email" => "1",
  "client_user_id" => "1",
  "email" => "john.smith@acme.com",
  "firstname" => "John",
  "lastname" => "Smith",
  "address" => "2134 Main Street",
  "city" => "Irvine",
  "state" => "CA",
  "zip" => "92620",
  "country" => "US",
  "phone" => "234-234-2345",
  "position" => "NA"
}

results = ApiClient.sso_member(
  member_info,
  File.read("file_path_to_private_key")
)

if results['status'] == 'ok'
  puts "Success!  Token URL: #{results['data']['token_url']}"
else
  puts "There were some errors: \n"
  results['error'].each do |key, value|
    puts "#{key}: #{value} \n"
  end
end
