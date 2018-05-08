
from awesomeware import app

if __name__ == "__main__":
    app.run('0.0.0.0', 5050,
            ssl_context=(
                '/etc/letsencrypt/live/team-exploit.me/fullchain.pem',
                '/etc/letsencrypt/live/team-exploit.me/privkey.pem'))

    
