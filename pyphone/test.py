import dotenv

env = dotenv.dotenv_values(".env")


print(env['USERNAME'])