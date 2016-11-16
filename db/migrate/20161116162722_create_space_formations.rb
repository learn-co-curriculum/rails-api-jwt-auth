class CreateSpaceFormations < ActiveRecord::Migration[5.0]
  def change
    create_table :space_formations do |t|
      t.string :image_url
      t.string :name
      t.string :description
      t.string :credit
      t.timestamps
    end
  end
end
