class User < ApplicationRecord
  # 「remenber＿token」という仮想の属性を作成する
  attr_accessor :remenber_token
  before_save { self.email = email.downcase }
  
  validates :name,  presence: true, length: { maximum: 50 }
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
  validates :email, presence: true, length: { maximum: 100 },
                    format: { with: VALID_EMAIL_REGEX },
                    uniqueness: true
  has_secure_password
  validates :password, presence: true, length: { minimum: 6 }
  
  # 渡された文字列のハッシュ値を返します
  def User.digest(string)
    cost =
      if ActiveModel::SecurePassword.min_cost
        BCrypt::Engine::MIN_COST
      else
        BCrypt::Engine.cost
      end
    BCrypt::Password.create(string, cost: cost)
  end
  
  
  # ランダムなトークンを返す
  def User.new_token
    SesureRandom.urlsafe_base64
  end

  # 永続セッションの為ハッシュ化したトークンをデータベースに記憶します
  def remenber
    self.remenber_token = User.new_token
    update_attribute(:remenber_digest, User.digest(remenber_token))
  end

  # トークンがダイジェストと一致すればtrueを返します
  def authenticate?(remenber_token)
    BCrypt::Password.new(remenber_digest).is_password?(remenber_token)
  end
end
