from datetime import timedelta 

class Config:
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://stephany:12345@localhost/biblioteca'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'supersecretkey'  
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)  
