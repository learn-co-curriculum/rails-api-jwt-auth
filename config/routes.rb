Rails.application.routes.draw do
  namespace :api do 
    namespace :v1 do 
      resources :space_formations
    end
  end

  post '/login', to "sessions#create"
end
