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

If you run `rake db:create; rake db:migrate; rake db:seed` and then point your browser to `http://localhost:3000/api/v1/space_formations`, you should see this:

![]()

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
    user = User.find(auth_params[:email])
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



















































































