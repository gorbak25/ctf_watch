#!/usr/bin/env python3
#Slack bot for monitoring CTF Platforms

import requests
import time
import sys
import traceback
from abc import ABC, abstractmethod
import re

class Slack:
    def __init__(self, public_webhook, admin_webhook):
        # webhook for ctf channel
        self.public_webhook = public_webhook

        #webhooks for admins
        self.admins_webhooks = admin_webhook

    def post_message(self, message, webhook):
        r = requests.post(webhook, json={"text": message})
        if (r.status_code != 200):
            raise RuntimeError("Failed to post slack message")

    def notify_admins(self, message):
        for admin in self.admins_webhooks:
            self.post_message(message, admin)

    def notify_channel(self, message):
        self.send_to_channel("<!channel>\n"+message)

    def send_to_channel(self, message):
        self.post_message(message, self.public_webhook)

    def notify_all(self, message):
        self.notify_admins(message)
        self.notify_channel(message)

class Challenge:
    def __init__(self, category, name, value, num_of_hints, solved = False):
        self.category = category
        self.name = name
        self.value = value
        self.num_of_hints = num_of_hints
        self.solved = solved

class Team:
    def __init__(self, pos, name, score):
        self.pos = pos
        self.name = name
        self.score = score

class CTFPlatform(ABC):
    def __init__(self, url, team_name, password):
        self.url = url
        self.team_name = team_name
        self.password = password

        self.login()

        super().__init__()

    @abstractmethod
    def login(self):
        pass

    @abstractmethod
    def poll_game_state(self):
        pass

    @abstractmethod
    def poll_scoreboard(self):
        pass

#https://ctfd.io/
class CTFD(CTFPlatform):
    def get_request(self, endpoint, **kwargs):
        return self.session.get(self.url + endpoint, **kwargs).text

    def get_json_api(self, endpoint, **kwargs):
        return self.session.get(self.url + endpoint, **kwargs).json()

    def post_request(self, endpoint, **kwargs):
        return self.session.post(self.url + endpoint, **kwargs).text

    def login(self):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:58.0) Gecko/20100101 Firefox/58.0"

        nonce = self.get_request("/login").split('nonce"')[1].split("value=\"")[1].split("\"")[0]
        self.post_request("/login", data={"name": self.team_name, "nonce": nonce, "password": self.password})

    def poll_game_state(self):
        chals = self.get_json_api("/chals")["game"]
        solved = self.get_json_api("/solves")["solves"]

        chals_state = {}
        for state in chals:
            chals_state[state['name']] = Challenge(state['category'], state['name'], state['value'], len(state['hints']))

        for chal in solved:
            chals_state[chal['chal']].solved = True

        return chals_state

    def poll_scoreboard(self):
        data = self.get_json_api("/scores")["standings"]
        better_teams = {}
        worse_teams = {}

        mode = False
        our_team = None
        for entry in data:
            team = Team(entry['pos'], entry['team'], entry['score'])
            if team.name == self.team_name:
                our_team = team
                mode = True
            elif mode:
                worse_teams[team.name] = team
            else:
                better_teams[team.name] = team

        return better_teams, our_team, worse_teams

#https://github.com/themis-project/themis-quals
class ThemisQuals(CTFPlatform):
    def get_challenge_properties_from_div(self, div):
        challenge_name = div.split("\"#submit-task-modal\">\n")[1].split("</h5>")[0].strip()
        challenge_value = int(div.split("\"themis-task-value\">\n")[1].split("</div>")[0].strip())
        challenge_category = div.split("&nbsp;")[1].split("</span>")[0].strip()
        challenge_solved = "bg-success" in div.split("</h5>")[0]

        challenge_id = int(div.split('\"')[0])
        challenge_hints = len(self.get_json_api("/api/task/{}/hint".format(challenge_id)))

        return Challenge(challenge_category, challenge_name, challenge_value, challenge_hints, challenge_solved)

    def get_team_properties_from_entry(self, entry):
        team_pos = int(entry.split("<th scope=\"row\">")[1].split("</th>")[0])
        team_name = entry.split("class=\"themis-team-link\">")[1].split("</a>")[0]
        team_score = int(entry.split("<td>")[2].split("</td>")[0])

        return Team(team_pos, team_name, team_score)

    def get_request(self, endpoint, **kwargs):
        text =  self.session.get(self.url + endpoint, **kwargs).text
        if "\"token\":\"" in text:
            csrf_token = text.split("\"token\":\"")[1].split("\"")[0]
            self.session.headers["X-CSRF-Token"] = csrf_token
        return text

    def get_json_api(self, endpoint, **kwargs):
        return self.session.get(self.url + endpoint, **kwargs).json()

    def post_request(self, endpoint, **kwargs):
        return self.session.post(self.url + endpoint, **kwargs).text

    def login(self):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:58.0) Gecko/20100101 Firefox/58.0"

        self.get_request("") #get a csrf token

        r = self.post_request("/api/team/signin", data={"password": self.password, "team": self.team_name})
        if "{\"success\":true}" != r:
            raise RuntimeError("Invalid login")

    def poll_game_state(self):
        front = self.get_request("/tasks")
        front = front.split("themis-task-preview-container\" data-task-id=\"")[1:-1]

        chals_state = {}
        for div in front:
            chal = self.get_challenge_properties_from_div(div)
            chals_state[chal.name] = chal

        return chals_state

    def poll_scoreboard(self):
        page = self.get_request("/scoreboard")
        page = page.split("<tbody id=\"themis-scoreboard-table-body\">")[1].split("</tbody>")[0]
        entries = page.split("<tr class=\"themis-scoreboard-row")[1:]

        better_teams = {}
        worse_teams = {}

        mode = False
        our_team = None
        for entry in entries:
            team = self.get_team_properties_from_entry(entry)
            if team.name == self.team_name:
                our_team = team
                mode = True
            elif mode:
                worse_teams[team.name] = team
            else:
                better_teams[team.name] = team

        return better_teams, our_team, worse_teams

class Bot:
    def __init__(self, configuration):
        self.ctf = configuration["CTF_PLATFORM"](configuration["CTF_URL"], configuration["CTF_LOGIN"], configuration["CTF_PASSWORD"])
        self.slack = Slack(configuration["SLACK_CHANNEL_WEBHOOK"], configuration["SLACK_ADMIN_WEBHOOK"])
        self.polling_interval = configuration["POLLING_INTERVAL"]
        self.game_state = self.ctf.poll_game_state()
        self.better_teams, self.our_team, self.worse_teams = self.ctf.poll_scoreboard()

        self.slack.notify_all("Bot started for team \"{}\"\nPolling CTF state every {} seconds".format(self.ctf.team_name, self.polling_interval))

        self.loop()

    def loop(self):
        while(1):
            try:
                time.sleep(self.polling_interval)
                cur_state = self.ctf.poll_game_state()
                cur_better_teams, cur_our_team, cur_worse_teams = self.ctf.poll_scoreboard()

                for chal in cur_state.keys():
                    # look for new challenges
                    if chal not in self.game_state:
                        chal = cur_state[chal]
                        self.slack.notify_channel("New challenge published!\nName: {}\nCategory: {}\nPoints: {}".format(
                            chal.name, chal.category, chal.value))

                    # look for solved challenges
                    elif not self.game_state[chal].solved and cur_state[chal].solved:
                        chal = cur_state[chal]
                        self.slack.notify_channel("Challenge {} was solved\nWe gained {} points\n We are currently on position {} with {} points".format(
                            chal.name,
                            chal.value,
                            cur_our_team.pos,
                            cur_our_team.score))
                    # check if we lost some points
                    elif self.game_state[chal].solved and not cur_state[chal].solved:
                        chal = cur_state[chal]
                        self.slack.notify_channel("Warning we just lost {} points for {} !".format(chal.value, chal.name))

                    # look for new hints
                    elif self.game_state[chal].num_of_hints < cur_state[chal].num_of_hints:
                        self.slack.notify_channel("New hint available for {}".format(chal))

                    # look for removed hints
                    elif self.game_state[chal].num_of_hints > cur_state[chal].num_of_hints:
                        self.slack.notify_channel("Warning hint for {} was removed!".format(chal))

                # look for removed challenges
                for chal in self.game_state.keys():
                    if chal not in cur_state:
                        self.slack.notify_channel("Warning challenge {} was removed from the game!".format(chal))

                # we were surpassed by someone
                if cur_our_team.pos < self.our_team.pos and cur_our_team.score == self.our_team.score:
                    diff = filter(lambda entry: entry[0] not in self.better_teams, cur_better_teams.items())
                    diff = map(lambda entry: "We were surpassed by {} by {} points"(
                        entry[0],
                        entry[1].score - cur_our_team.score), diff)
                    diff = '\n'.join(diff)

                    self.slack.notify_channel("We are currently on position {} with {} points\n".format(cur_our_team.pos, cur_our_team.score)+diff)

                # we surpassed someone
                elif cur_our_team.pos > self.our_team.pos and cur_our_team.score != self.our_team.score :
                    diff = filter(lambda entry: entry[0] in cur_worse_teams, self.better_teams.items())
                    diff = map(lambda  entry: "We surpassed {} by {} points".format(
                        entry[0],
                        cur_our_team.score - entry[1].score), diff)
                    diff = '\n'.join(diff)

                    self.slack.send_to_channel(diff)

                #check our leadership
                elif len(cur_worse_teams) > 0 and len(self.worse_teams) and cur_our_team.score == self.our_team.score:
                    prev_worse_score = max(map(lambda entry: entry[1].score, self.worse_teams.items()))
                    cur_worse = max(map(lambda entry: (entry[0], entry[1].score), cur_worse_teams.items()), key=lambda el: el[1])

                    if (self.our_team.score - prev_worse_score) > (cur_our_team.score - cur_worse[1]):
                        self.slack.notify_channel("Warning our leadership dropped!\nTeam {} now needs at least {} points to surpass us".format(
                            cur_worse[0],
                            cur_our_team.score - cur_worse[1]))

                self.game_state = cur_state
                self.better_teams = cur_better_teams
                self.our_team = cur_our_team
                self.worse_teams = cur_worse_teams

            except KeyboardInterrupt:
                self.slack.notify_all("Bot was terminated\nBye!")
                exit(0)
            except Exception as ex:
                print("Exception", ex)
                print(traceback.format_exc())
                self.slack.notify_all("Something went wrong - check bot")
                exit(-1)

if __name__ == "__main__":
    if(len(sys.argv)) != 2:
        print("Usage ./bot.py [configuration_file]")
        exit(0)

    # https://stackoverflow.com/questions/7160737/python-how-to-validate-a-url-in-python-malformed-or-not
    url_regex = re.compile(
        r'^(?:http)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    # ----------------------------- End of C&P ---------------

    def check_url(url):
        if not url_regex.match(url):
            raise RuntimeError("Invalid URL {}".format(url))

    configuration = {}
    configuration['SLACK_ADMIN_WEBHOOK'] = []

    try:
        with open(sys.argv[1], 'r') as f:
            for line in iter(f.readline, ''):
                entry = [e.strip() for e in line.split(':') if e != '']
                entry = [entry[0], ':'.join(entry[1:])]
                if entry[0] == "SLACK_ADMIN_WEBHOOK":
                    check_url(entry[1])
                    configuration[entry[0]].append(entry[1])
                elif entry[0] == "SLACK_CHANNEL_WEBHOOK":
                    check_url(entry[1])
                    configuration[entry[0]] = entry[1]
                elif entry[0] == "POLLING_INTERVAL":
                    configuration[entry[0]] = int(entry[1])
                elif entry[0] == "CTF_PLATFORM":
                    if entry[1] == "CTFD":
                        configuration[entry[0]] = CTFD
                    if entry[1] == "ThemisQuals":
                        configuration[entry[0]] = ThemisQuals
                    else:
                        raise RuntimeError("Warning Unknown CTF Platform")
                elif entry[0] == "CTF_URL":
                    check_url(entry[1])
                    configuration[entry[0]] = entry[1]
                else:
                    configuration[entry[0]] = entry[1]
        Bot(configuration)
    except Exception as ex:
        print("Exception:", ex)
        print(traceback.format_exc())
        print("Invalid configuration file")
        exit(-1)
