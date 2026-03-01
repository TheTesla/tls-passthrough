import redis
import os
import uuid

r = redis.Redis(
    host=os.getenv("REDIS_HOST", "redis"),
    port=6379,
    decode_responses=True
)

def get_user_by_github(github_id):
    user_id = r.get(f"github:{github_id}")
    if not user_id:
        return None
    return r.hgetall(f"user:{user_id}")

def create_user(github_id, username):
    user_id = str(uuid.uuid4())

    r.hset(f"user:{user_id}", mapping={
        "github_id": github_id,
        "username": username,
        "role": "user"
    })

    r.set(f"github:{github_id}", user_id)

    return user_id

def get_user(user_id):
    return r.hgetall(f"user:{user_id}")
