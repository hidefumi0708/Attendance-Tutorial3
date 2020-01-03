class UsersController < ApplicationController
  
  def show
    @user = User.find(params[:id])
    # debugger # インスタンス変数を定義した直後にこのメソッドが実行される。
  end
  
  
  def new
    @user = User.new # ユーザーオブジェクトを生成し、インスタンス変数に代入する。
  end
end
