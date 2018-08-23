import pymysql

def consulta_BD(query):
	""" Connect to MySQL database """
	conn = pymysql.connect(host="us-cdbr-iron-east-01.cleardb.net",
						user="b525f0b4bca0a4",
						passwd="e7ecea88",
						db="heroku_01a9862c25f7015",
						charset='utf8mb4',
						cursorclass=pymysql.cursors.DictCursor)
	cursor = conn.cursor()
	rows = []
	try:
		cursor.execute(query)
		rows = cursor.fetchall()
	except pymysql.Error as e:
		print ("Error", e)
		conn.rollback()

	cursor.close()
	conn.close()

	return rows

def update_BD(query):
	""" Connect to MySQL database """
	conn = pymysql.connect(host="us-cdbr-iron-east-01.cleardb.net",
						user="b525f0b4bca0a4",
						passwd="e7ecea88",
						db="heroku_01a9862c25f7015",
						charset='utf8mb4',
						cursorclass=pymysql.cursors.DictCursor)
	cursor = conn.cursor()
	try:
		cursor.execute(query)
		conn.commit()
	except pymysql.Error as e:
		print ("Error", e)
		conn.rollback()

	cursor.close()
	conn.close()

	return 'Dados adicionados!'