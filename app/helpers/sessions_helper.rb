module SessionsHelper

  # 引数に渡されたユーザーオブジェクトでログインします。
  def log_in(user)
    session[:user_id] = user.id
  end


  # 永続セッションを記憶します(Userモデルを参照)
  def remenber(user)
    user.remenber
    cookies.permanent.signed[:user_id] = user.id
    cookies.permanent[:remenber_token] = user.remenber_token
  end

  # 永続的セッションを破棄する
  def forget(user)
    user.forget # Userモデル参照
    cookies.delete(:user_id)
    cookies.delete(:remenber_token)
  end
  
  
  
  
  # セッションと@current_usreを破棄します
  def log_out
    forget(current_user)
    session.delete(:user_id)
    @current_user = nil
  end


  # 一時的セッションにいるユーザーを返します。
  # それ以外の場合はcookiesに対応するユーザーを返します。
  def current_user
    if (user_id = session[:user_id])
      @current_user ||= User.find_by(id: user_id)
    elsif (user_id = cookies.signed[:user_id])
      user = User.find_by(id: user_id)
      if user && user.authenticated?(cookies[:remember_token])
        log_in user
        @current_user = user
      end
    end
  end

  # 渡されたユーザーがログイン済みのユーザーであればtrueを返す
  def current_user?(user)
    user == current_user
  end
  
  
  
  # 現在ログイン中のユーザーがいればtrue、そうでなければfalseを返します。
  def logged_in?
    !current_user.nil?
  end

  # 記憶しているURL（またはデフォルトURL）にリダイレクトする
  def redirect_back_or(default_url)
    redirect_to(session[:forwarding_url] || default_url)
    session.delete(:forwarding_url)
  end

  # アクセスしようとしたURLを記憶する
  def store_location
    session[:forwarding_url] = request.original_url if request.get?
  end

end