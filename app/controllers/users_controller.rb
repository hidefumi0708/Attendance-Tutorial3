class UsersController < ApplicationController
  before_action :set_user, only: [:show, :edit, :update, :destroy]
  before_action :logged_in_user, only:[:show, :edit, :update, :destroy]
  before_action :correct_user, only:[:edit, :update]
  before_action :admin_user, only: :destroy
  
  def index
    @users = User.paginate(page: params[:page])
  end
  
  
  def show
    @user = User.find(params[:id])
    # debugger # インスタンス変数を定義した直後にこのメソッドが実行される。
  end
  
  
  def new
    @user = User.new # ユーザーオブジェクトを生成し、インスタンス変数に代入する。
  end
  
  def create
    @user = User.new(user_params)
    if @user.save
      log_in @user # 保存成功後、ログインします。
      flash[:success] = '新規作成に成功しました'
      redirect_to @user
    else
      render :new
    end
  end
  
  def edit
    @user = User.find(params[:id])
  end
 
 
  def update
    @user = User.find(params[:id])
    if @user.update_attributes(user_params)
      flash[:success] = "ユーザー情報を更新しました。"
      redirect_to @user
    else
      render :edit
    end
  end
 
 
  def destroy
    @user.destroy
    flash[:success] = "#{@user.name}のデータを削除しました。"
    redirect_to users_url
  end
 
 
  private
  
    def user_params
      params.require(:user).permit(:name, :email, :password, :password_confirmation)
    end


  # beforeフィルター
  
  # paramsハッシュからユーザーを取得
    def set_user
      @user = User.find(params[:id])
    end
  
  
  # ログイン済みのユーザーか確認する
  def logged_in_user
    unless logged_in?
      store_location
      flash[:danger] = "ログインしてください。"
      redirect_to login_url
    end
  end

  # アクセスしたユーザーが現在ログインしているユーザーか確認します
  def correct_user
    @user = User.find(params[:id])
    redirect_to(root_url) unless current_user?(@user)
  end

  # システム管理権限所有化どうか判定する
  def admin_user
    redirect_to root_url unless current_user.admin?
  end
end
