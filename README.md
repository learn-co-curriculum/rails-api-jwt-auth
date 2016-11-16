# JWT Authentication in Rails API

## Objectives

* Understand why we need a non-session based authentication system in a Rails API
* Understand what JWT (JSON Web Tokens) are and how to implement them to authorize users in a Rails API
* Use Postman to interact with your API


## Introduction

When building client-side applications with front-end frameworks (like React), we have a number of options for getting data--we can use a third-party API like the Spotify API or NYC Open Data APIs. But often we'll need to develop and serve our own data to our front-end apps. In this case, Rails 5 API is a great option. With the Rails 5 "api only" feature, we can quickly spin up an API that serves our very own custom data. Then, we can tell our client-side apps to simply request this data from our Rails app. 

Authenticating between our separate client-side and server sides apps can provide an interesting challenge, however. 

In a normal (i.e. non-API) Rails app, we "log in" a user by storing their unique user ID in the session store. This means that authentication information is stored on the server side, in the session hash. In other words, our server becomes stateful, keeping track of whether or not a user is "logged in", and who that user is.

In an API, however, we aim to keep our server "stateless". It should not retain information from previous web requests. On top of that, Rails 5 *does not ship with access to the session store*. While you could add it back in by following these steps, it's not really in-line with the stateless API philosophy to do so. 

So, we need a way to authenticate users and authorize incoming requests, all without using the Rails session store. 

JWT authentication provides one such option. Let's take a look. 

## What is JWT?

> JSON Web Token (JWT) Authentication is a compact, URL-safe means of representing claims to be transferred between two parties. The claims in a JWT are encoded as a JSON object that is used as the payload of a JSON Web Signature (JWS) structure or as the plaintext of a JSON Web Encryption (JWE) structure, enabling the claims to be digitally signed or integrity protected with a Message Authentication Code (MAC) and/or encrypted.[*](https://tools.ietf.org/html/rfc7519)

In plain English, JWT allows us to authenticate requests between the client and the server by encrypting authentication information into a compact JSON object. Instead of, say, passing a user's own unique token (which we would need to persist to the database), or (god forbid), sending a user's raw email and password with every authentication request, JWT allows us to encrypt a user's identifying information, store it in a token, inside a JSON object, and include that object in every request that requires authentication.

Let's take a closer look at how that cycle might work, using the example of a React app + Rails API.

* User fills out the log in form via the React app and hits "log in!"
* React POSTs user's email and password to the Rails API.
* Rails receives the POST request and and queries the database for the right user. If the user can be authenticated...
* We'll use JWT to encrypt that user's unique ID into a compact and secure JSON Web Token.
* This token is then included in the response that Rails sends back to React.
* React stores the encrypted JWT token in the browser's local or session storage, retrieving it and sending it back to Rails, as the HTTP Authentication header, in any authenticated requests.

So, what's so great about this system?

Well, for one thing, we are not storing a unique user token in our database. Instead, we are encrypting the user's unique identifying info in our token, and decrypting it on the Rails side when we need to identify the "current user". Secondly, our server is not responsible for keeping track of the current user, as is the case when we use Rails' session object.

If you're not yet convinced of how great this is, check out the [jwt.io documentation](https://jwt.io/). It offers some very clear and concise info.

## JWT Encryption: How Does it Work?

JWT tokens are encrypted in three parts:

* The header: the meta-data describing the encryption algorithm and type of token
* The payload: the actual data concerning the user (id, email, etc.)
* The signature: special combo of header info + payload to ensure that the sender of the token is really you!

Let's take a look at an example, using the JWT Ruby library to encode our very own token!

Given this information:

```ruby
{user_id: 1}
hmac_secret = $39asdulawk3j489us39vm9370dmsZ
encryption_algorithm = HS256
```
We can encrypt our token in the following way:

```ruby
require 'jwt'

JWT.encode(  
  {user_id: 1}, 
   hmac_secret,
   encryption_algorithm)
```

And it will return our three part JWT:

```ruby
QyJ0asdfjos.ald925lIn0.eyJ0ZXN0Ijas39uZGF0YSJ9.
```

Similarly, to decode our token, we can use the following JWT Ruby code, where token is set equal to the above JWT, and hmac is set equal to the hmac secret we used to encrypt that token:

```ruby
JWT.decode(token, hmac, "H256")

=> [
     {"user_id"=>"1"},
     {"typ"=>"JWT", "alg"=>"HS256"}
]
```

As we've seen here, it's not too complicated to implement JWT in Ruby. So, let's get started on implementing it in Rails.

## Code Along: Implementing JWT Auth in Rails 5 API

Clone down this repo to get started. We'll be using a super cool tool called Postman to send requests to our API as we develop our authentication feature. Postman can mimic the whole "user filling out a form in our separate React (or whatever) client-side app". This way, we can test that our app really works as it should when being sent requests by a real client-side app. 

We'll walk you through how to use Postman as we go, but go ahead and [download it here](https://www.getpostman.com/) if you don't have it already.

### App Background

This repo contains a simple Rails 5 API that serves data on a few interesting outerspace formations--stars, nebulas, galaxies, that kind of thing. We have one model, `SpaceFormation`, and each space formation has a name, description and image URL. 

If you run `rake db:create; rake db:migrate; rake db:seed` and then point your browser to `http://localhost:3000/api/v1/space_formations`, you should see all our great outer space data.

Right now, this information is totally unprotected! Anyone can vist the above URL and see our precious space info. We'll fix this by setting up our authentication system. 

Here's how it will work: 

* A user will fill out a log in form from a totally separate client-side application
* This will send a `POST` request to the `SessionsController` of our Rails API. 
* The `create` action of the `SessionsController` will authenticate the user using BCrypt. If the user can be authenticated...
* We'll generate a JWT and send it back to the client-side app that sent the log in request. 
* Our client-side app will use this token to make subsequent authorized requests. It will put the token in a request header and our Rails APP will check incoming requests for the presence of this header and JWT. If the header is present and contains a valid JWT, Rails will let the request through. 

### Step 1: Setting Up the User Model

First things first, we need to create a user model and add BCrypt. 

```
rails g model user first_name:string last_name:string email:string password_digest:string
```
Then run `rake db:migrate`. 

Next up, add `gem 'bcrypt'` to your Gemfile and `bundle install`. 

Then, add the `has_secure_password` macro to your `User` model.

Now we're ready to set up our `SessionsController`. 

### Step 2: Setting Up the `SessionController` and Log In Route

We'll define our log in route in the `routes.rb` file:

```ruby
# config/routes.rb

Rails.application.routes.draw do
  namespace :api do 
    namespace :v1 do 
      resources :space_formations
    end
  end

  post '/login', to "sessions#create"
end
```

Most of our sessions controller is going to look pretty familiar. 

```ruby
class SessionsController < ApplicationController
  def create
    user = User.find_by(email: auth_params[:email])
    if user.authenticate(auth_params[:password])
      # here we will encrypt our token and serve it as part of the JSON response
    else
      render json: {error: 'incorrect email or password'}, status: 401
    end
  end

  private

  def auth_params
    params.require(:auth).permit(:email, :password)
  end
end
```

We accept our `auth_params`, which will contain the email and password of the user trying to log in. Then we authenticate the user using BCrypt's `#authenticate` method. 
If we can authenticate the user, we will then encrypt and return the JWT. Otherwise, we'll return that helpful error message.

Now that our sessions controller is more or less in place, we're ready to set up our custom JWT implementation, so that we can encrypt user info. 

### Step 3: Building a JWT Auth Library


Since we'll need to regularly encode and decode JWTs, it makes sense to write a plain old Ruby class (PORO), that will wrap up some of that functionality. 

We'll put this class, which we'll call Auth, inside our `lib/` directory. 

* Add the jwt gem to your Gemfile and bundle install:

```ruby
# Gemfile

gem 'jwt'
```
* Create a file `lib/auth.rb`
* Add your `lib/` directory to the Rails autoload path:

```ruby
# config/application.rb

config.autoload_paths << Rails.root.join('lib')
```

* Define your Auth class to have a method, `.issue`, which will be responsible for generating a JWT from a given user's information, and a `.decode` method, which will decode a given JWT:

```ruby
require 'jwt'

class Auth

  def self.issue(payload)
    
  end

  def self.decode(token)
    
  end

end
```

We'll start with our `.issue` method.

#### Generating a JWT: `Auth.issue`

This method will simply wrap the `JWT.encode` method that the jwt gem makes available to us. This method takes in three arguments:

* The data, in the form of a hash, that you will to encode in the JWT
* The key to your hashing algorithm
* The type of hashing algorithm 

For example:

```ruby
payload = {name: "sophie"}
secret_key = "masd82348$asldfja"
algorithm = "HS256"

JWT.encode(payload, secret_key, algorithm)
=> "esdiva23euihrusdfcnkjz2snciusdhuihr7480y2qikjh8"
``` 

Tada!

How, though, will we generate a super secret key? 

###### Generating a Hashing Key

We'll use the Digest module that is native to Ruby to generate our secret key. We'll generate our key in the command line, in the Pry console, and add it to our environment as an environment variable. We'll use Figaro to make sure that environment variable doesn't get pushed up to GitHub. 

```bash
$ pry 
pry > Digest::SHA256.digest('beyonce')
 => "\x85\x11\xFA\xEF\xF2A\x11\xC7\x90\x9C!{\xDC\x11W\xFB\x93\xE5\xA3\xCD\xE3\xC2\x9E#7\xC4\xCDa\xCF\xC9/\xEA"
```

Add `gem 'figaro'` to your Gemfile and `bundle install`. 

Then, from the command line run `figaro install`. This will generate the `application.yml` file *and* add it to your `.gitignore`.

We'll add it to our secret key `application.yml` like this:


```ruby
# config/application.yml
AUTH_SECRET: \x85\x11\xFA\xEF\xF2A\x11\xC7\x90\x9C!{\xDC\x11W\xFB\x93\xE5\xA3\xCD\xE3\xC2\x9E#7\xC4\xCDa\xCF\xC9/\xEA
```

Okay, now we're ready to finish up that `Auth.issue` method. 

*Note: You can also generate a secret in Rails by running `rake secret` in the command line in the directory of your app*.

###### `Auth.issue`

```ruby
# lib/auth.rb
require 'jwt'

class Auth

  ALGORITHM = 'HS256'

  def self.issue(payload)
    JWT.encode(
      payload,
      auth_secret,
      ALGORITHM)
  end

  def self.decode(token)

  end

  def self.auth_secret
    ENV["AUTH_SECRET"]
  end
end
```

*Notice that the hashing algorithm is stored in a class constant, `ALGORITHM`. This is because our `.decode` method will also need to access that information. Similarly, we've wrapped our accessing of the `ENV["AUTH_SECRET"]` in a method call, because we'll also need that data for our `.decode` method*

While we're here, let's define that decode method. 

#### Decoding a JWT: `Auth.decode`

Our `Auth.decode` method will simply wrap the `JWT.decode` method that the jwt gem makes available to us. This method takes in three arguments:

* The JWT that we want to decode, 
* The hashing algorithm's secret key
* The type of hashing algorithm

```ruby
# lib/auth.rb
require 'jwt'

class Auth

  ALGORITHM = 'HS256'

  def self.issue(payload)
    JWT.encode(
      payload,
      auth_secret,
      ALGORITHM)
  end

  def self.decode(token)
    JWT.decode(token, 
      auth_secret, 
      true, 
      { algorithm: ALGORITHM }).first
  end

  def self.auth_secret
    ENV["AUTH_SECRET"]
  end
end
```

Okay, now we're ready to use our Auth library in our sessions controller. 

### Step 4: Authorizing a User in the Sessions Controller

We already built out quite a bit of our `Sessions#create` action. Now we're ready to add in the lines of code that will issue a JWT if the user can be authenticated, and return the JWT as JSON. 

```ruby
# app/controllers/sessions_controller.rb
class SessionsController < ApplicationController

  skip_before_action :authenticate

  def create
    user = User.find_by(email: auth_params[:email])
    if user.authenticate(auth_params[:password])
      jwt = Auth.issue({user_id: user.id})
      render json: {jwt: jwt}
    else
    end
  end

  private
    def auth_params
      params.require(:auth).permit(:email, :password)
    end
```

Here, we use the data in the `auth_params` to authorize our user via bcrypt. If the user can be authenticated, we generating our JWT, using the Auth library we just defined. Here's the line where the magic happens:

```ruby
jwt = Auth.issue({user: user.id})
```

Note that we are encrypting the user's ID, not an email and password. This is because the user's ID is a unique identifier without being sensitive information (like a password).

*Note: my `auth_params` are grabbing data that is nested under the `auth` key. This imeans that the client that sends the `POST` request to `/login` will have to structure the request body to reflect this nested structure.*

Then, we are sending the JWT back to the client-side app, as JSON, where it will be stored in the brower's storage. 

Okay, we're ready to use Postman to try this out. 

#### Testing It Out With Postman

First, open up the Rails console via `rails c` in your terminal and create one dummy user.

Now go ahead and open up Postman on your computer. 

We'll make Postman send a log in request by selected `POST` request from the drop down menu on the left, entering the URL, `http://loclahost:3000/login`, and structuring our params via the request body. 

![](https://s3-us-west-2.amazonaws.com/curriculum-content/web-development/react/Screen+Shot+2016-11-16+at+2.32.07+PM.png)

Notice that the `Body` option is selected on the list of options below the URL bar, the `raw` option is selected below that and the `JSON(application/json)` option is selected to the right of that. 

Fill our your request body to mirror the structure that our sessions controller strong params is expecting:

```json
{"auth": {"email": "the email of your dummy user", "password": "the password of your dummy user"}}
```

Hit the big blue `Send` button and scroll down to see your response. You should see your JWT returned to you!

![](https://s3-us-west-2.amazonaws.com/curriculum-content/web-development/react/Screen+Shot+2016-11-16+at+2.38.09+PM.png)

### Step 4: Building our Authorization System

Now that users are able to "log in", i.e. get a JWT and store it for future use, we need to reach Rails how to check incoming requests for the presence of that JWT and only allow users to see our amazing space formation data if a valid token is present.

First, we'll set up the basic structure of our application controller

#### The Application Controller

The basic structure should look familiar:

```ruby
# app/controllers/application_controller.rb

class ApplicationController < ActionController::API  
  before_action :authenticate 
  
  def logged_in?
    !!current_user
  end
  
  def current_user
    # if the authorization header is present AND if it contains a valid JWT, set the current user
  end
  
  def authenticate
    render json: {error: "unauthorized"}, status: 401 unless logged_in?
  end
  
  
end  
```

We define a before action, called `authenticate`, that will send back an error message if the user who sent the request is not considered to be logged in. 

Our `logged_in?` method checks to see whether or not we have a current user.

How would we determine whether or not there is a "current user"? 

We will check all incoming web requests for the presence of an authorization header with a value of `Bearer <some jwt token>`. If that header is present, we'll grab the token and decode it. If we can decode it and get a valid user ID, then we have a current user!

Let's build out some helper methods to make this work. 

**Note:** Make sure you add a `skip_before_action :authenciate` to your Session Controller, otherwise no one will ever be able to log in!

#### Defining the `current_user` Method

Okay, so, if our client-side app is set up properly, all subsequent requests to our API will include the following header:

```ruby
"HTTP_AUTHORIZATION" => "Bearer <super encoded JWT>"
``` 

So, our `current_user` method, which we'll define in the Application Controller, will need to decode the JWT. Let's do it. 

```ruby
# app/controllers/application_controller.rb

class ApplicationController < ActionController::API
  before_action :authenticate 

  def logged_in?
    !!current_user
  end

  def current_user
    if auth_present?
      user = User.find(auth["user_id"])
      if user
        @current_user ||= user
      end
    end
  end

  def authenticate
    render json: {error: "unauthorized"}, status: 401 unless logged_in?
  end

  private

    def token
      request.env["HTTP_AUTHORIZATION"].scan(/Bearer(.*)$/).flatten.last.strip
    end

    def auth
      Auth.decode(token)
    end

    def auth_present?
      !!request.env.fetch("HTTP_AUTHORIZATION", "").scan(/Bearer/).flatten.first
    end
end
```

Some of this code should look pretty familiar: the `current_user` method is in charge of retrieving the current user, the `logged_in?` method returns true or false, depending on the presence of a current user, and the `authenticate` method acts as a gatekeeper, returning an error to the client-side application if there is no logged in user. 

Let's dive in to our `current_user` method. 

* First, we check to see if our `request` object has a header, or a key, of ["HTTP_AUTHORIZATION"] *and* if the value of that header includes a realm designation of `Bearer`. If so...
* Grab the token out of the value of that header, which would be something like `"Bearer <encoded JWT>"`

![](https://s3-us-west-2.amazonaws.com/curriculum-content/web-development/react/Screen+Shot+2016-11-16+at+2.51.48+PM.png)

* Then, in our `#auth` method, we use our Auth library to decode the token:

```ruby
Auth.decode(token)
```

* Finally, we use the decoded token, which is now in the below format, and contains a user's unique ID

```ruby
{user_id: 1}
```

to find and authorize the current user. 

And that's it!

Let's test it out with Postman. 

Open up Postman and make a request to `http://localhost:3000/api/v1/space_formations`. Add a header of `Authorization` with a value of `Bearer <place your jwt from the response you got for your previous postman request>`. 

You should see all your great space data!

![](https://s3-us-west-2.amazonaws.com/curriculum-content/web-development/react/Screen+Shot+2016-11-16+at+2.56.31+PM.png)

But, if you go to the browser and try to make the same request, i.e. a request without the proper authorization header and JWT, you should see an error message:

![](https://s3-us-west-2.amazonaws.com/curriculum-content/web-development/react/Screen+Shot+2016-11-16+at+2.58.36+PM.png)



















































































