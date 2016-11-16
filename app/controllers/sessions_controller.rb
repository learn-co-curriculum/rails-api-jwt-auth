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