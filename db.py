import psycopg2


def connection():
    try:
        conn = psycopg2.connect(
            host="localhost", database="postgres", user="postgres", password="root"
        )
        cur = conn.cursor()

        create_user_query = """CREATE TABLE userdata (
        id SERIAL PRIMARY KEY,
        username VARCHAR(20) NOT NULL,
        password VARCHAR(20) NOT NULL
        )"""

        create_query = """CREATE TABLE files (
    file_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES userdata(id),  -- Foreign key reference to users table
    filename VARCHAR(255),
    file_path VARCHAR(255),  -- You can store the path to the file
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

"""

        cur.execute(create_query)

        # post_query = "INSERT INTO userdata (username, pass) VALUES (%s, %s);"
        # values = ("jaimin", "jmn@123")
        # cur.execute(post_query, values)

        conn.commit()
        print("Data inserted successfully!")
        return "Success"

    except Exception as e:
        print("err", e)

    finally:
        cur.close()
        conn.close()


print(connection())
