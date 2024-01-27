import subprocess

def get_latest_commit_info():
    try:
        # Run the git command to get the latest commit hash and date time
        output = subprocess.check_output(['git', 'log', '-n', '1', '--pretty=format:%H,%cd'])
        commit_hash, commit_date = output.decode().strip().split(',')

        return commit_hash, commit_date
    except subprocess.CalledProcessError:
        # Handle any errors that occur during the git command execution
        return None, None
