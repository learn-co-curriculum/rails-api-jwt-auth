module Api
  module V1
    class SpaceFormationsController < ApplicationController

      def index
        render json: SpaceFormation.all
      end
    end
  end
end