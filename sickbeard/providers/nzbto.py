# Author: Nic Wolfe <nic@wolfeden.ca>
# URL: http://code.google.com/p/sickbeard/
#
# This file is part of Sick Beard.
#
# Sick Beard is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Sick Beard is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Sick Beard.  If not, see <http://www.gnu.org/licenses/>.

import re
import time
import urllib
import datetime
import cgi
import os

from xml.dom.minidom import parseString
from xml.etree import ElementTree

import generic
import sickbeard

from sickbeard import classes, logger, show_name_helpers, helpers
from sickbeard import tvcache
from sickbeard import exceptions
from sickbeard.exceptions import ex

import requests
from bs4 import BeautifulSoup


class NZBto(generic.NZBProvider):

    def __init__(self):
        generic.NZBProvider.__init__(self, "NZBto")

        self.supportsBacklog = False
        self.cache = NNZBtoCache(self)
        self.url = 'http://nzb.to/'
        self.searchString = ''

        self.session = requests.Session()
        self.session.get("http://nzb.to")
        self.session.headers["Referer"] = "http://nzb.to/login"
        self.session.headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:20.0) Gecko/20100101 Firefox/20.0"

    def isEnabled(self):
        return sickbeard.NZBTO

    def _checkAuth(self):
        if not sickbeard.NZBTO_USER or not sickbeard.NZBTO_PASS:
            raise exceptions.AuthException("nzbto authentication details are empty, check your config")

    def _get_season_search_strings(self, show, season):
        # sceneSearchStrings = set(show_name_helpers.makeSceneSeasonSearchString(show, season, "NZBIndex"))

        # # search for all show names and episode numbers like ("a","b","c") in a single search
        # return [' '.join(sceneSearchStrings)]
        return [x for x in show_name_helpers.makeSceneSeasonSearchString(show, season)]

    def _get_episode_search_strings(self, ep_obj):
        # # tvrname is better for most shows
        # if ep_obj.show.tvrname:
        #     searchStr = ep_obj.show.tvrname + " S%02dE%02d"%(ep_obj.season, ep_obj.episode)
        # else:
        #     searchStr = ep_obj.show.name + " S%02dE%02d"%(ep_obj.season, ep_obj.episode)
        # return [searchStr]
        return [x for x in show_name_helpers.makeSceneSearchString(ep_obj)]

    def _get_title_and_url(self, item):
        title = item.tr.find("td", attrs={"class": "title"}).a.text
        dl = item.find("a", attrs={"title": "NZB erstellen"})
        if dl is None:
            # some items have no download link.
            return None, None

        url = 'http://nzb.to/' + dl["href"]
        logger.log('_get_title_and_url(), returns (%s, %s)' %(title, url), logger.DEBUG)
        logger.log('self.searchString=%s' %(self.searchString), logger.DEBUG)

        return title, url

    def _doSearch(self, curString, quotes=False, show=None):
        self.session.post("http://nzb.to/login.php",
                          data={"action": "login", "username": sickbeard.NZBTO_USER, "password": sickbeard.NZBTO_PASS,
                                "bind_ip": "on", "Submit": ".%3AEinloggen%3A.", "ret_url": ""})
        logger.log('sending login to nzb.to returned Cookie: {0}'.format(self.session.cookies.get_dict()), logger.DEBUG)

        term = re.sub('[\.\-\:]', ' ', curString).encode('utf-8')
        self.searchString = term
        if quotes:
            term = "\"" + term + "\""

        #http://nzb.to/?p=list&q=Shameless+S03E12+german&cat=13&sort=post_date&order=desc&amount=50
        params = {"q": term,
                  "sort": "post_date", #max 50
                  "order": "desc", #nospam
                  "amount": 50, #min 100MB
                  }

        searchURL = "http://nzb.to/?p=list&" + urllib.urlencode(params)

        logger.log(u"Search string: " + searchURL)

        logger.log(u"Sleeping 10 seconds to respect NZBto's rules")
        time.sleep(10)

        logger.log(u"CURRENT COOKIE: {0}".format(self.session.cookies.get_dict()))

        cookie_test = re.compile(r"[0-9]*-\d{1}-.*")
        if re.match(cookie_test, self.session.cookies.get("NZB_SID") ):
            logger.log("ERROR... COOKIE SEEMS NOT TO BE VALID", logger.ERROR)

        if curString == "cache":
            url = "http://nzb.to/?p=list&cat=13&sa_Video-Genre=3221225407&sort=post_date&order=desc&amount=100"
            logger.log(url)
            searchResult = self.session.get(url)
            #logger.log(u"{0}".format(searchResult))
        else:
            searchResult = self.session.post("http://nzb.to/?p=list", data=params)

        if not searchResult:
            logger.log("Search gave no results...")
            return []

        try:
            parsedXML = BeautifulSoup(searchResult.text)
            table_regex = re.compile(r'tbody-.*')
            items = parsedXML.findAll("tbody", attrs={"id": table_regex})
        except Exception, e:
            logger.log(u"Error trying to load NZBto RSS feed: " + ex(e), logger.ERROR)
            return []

        results = []

        #logger.log(u"PARSING RESULTS FROM NZBTO")
        for curItem in items:
            (title, url) = self._get_title_and_url(curItem)

            if not title or not url:
                logger.log(u"One result returned from the nzb.to is incomplete, this result is unusable.",
                           logger.ERROR)
                continue
            if not title == 'Not_Valid':
                results.append(curItem)

        return results

    def findPropers(self, date=None):
        results = []
        # TODO: pubDate seems to be removed
        """
        for curResult in self._doSearch("(PROPER,REPACK)"):

            (title, url) = self._get_title_and_url(curResult)

            pubDate_node = curResult.getElementsByTagName('pubDate')[0]
            pubDate = helpers.get_xml_text(pubDate_node)
            dateStr = re.search('(\w{3}, \d{1,2} \w{3} \d{4} \d\d:\d\d:\d\d) [\+\-]\d{4}', pubDate)
            if not dateStr:
                logger.log(u"Unable to figure out the date for entry "+title+", skipping it")
                continue
            else:
                resultDate = datetime.datetime.strptime(dateStr.group(1), "%a, %d %b %Y %H:%M:%S")

            if date == None or resultDate > date:
                results.append(classes.Proper(title, url, resultDate))
        """
        return results

    def getResult(self, episodes):
        """
        Returns a result of the correct type for this provider
        """
        result = classes.NZBDataSearchResult(episodes)
        result.provider = self

        return result

    def findEpisode(self, episode, manualSearch=False):
        results = super(NZBto, self).findEpisode(episode, manualSearch)

        for result in results:
            result.extraInfo.append(NZBDownloader(result, self.session))

        return results

    def findSeasonResults(self, show, season):
        results = super(NZBto, self).findSeasonResults(show, season)

        for epNum, ep_results in results.items():
            for result in ep_results:
                result.extraInfo.append(NZBDownloader(result, self.session))

        return results


class NNZBtoCache(tvcache.TVCache):

    def __init__(self, provider):

        tvcache.TVCache.__init__(self, provider)

        # only poll nzb.to every 40 minutes max
        self.minTime = 40

        self.session = requests.Session()
        self.session.get("http://nzb.to")
        self.session.headers["Referer"] = "http://nzb.to/login"
        self.session.headers[
            "User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:20.0) Gecko/20100101 Firefox/20.0"

    def _parseItem(self, item):
        title, url = self.provider._get_title_and_url(item)
        logger.log(u"Adding item from RSS to cache: " + title, logger.DEBUG)
        self._addCacheEntry(title, url)

    def updateCache(self):
        if not self.shouldUpdate():
            return
        # get all records since the last timestamp
        #
        if not sickbeard.NZBTO_USER or not sickbeard.NZBTO_PASS:
            raise exceptions.AuthException("nzbto authentication details are empty, check your config")
        else:
            #if user and pass are ok, log us in
            self.provider.session.post("http://nzb.to/login.php",
                                       data={"action": "login", "username": sickbeard.NZBTO_USER,
                                             "password": sickbeard.NZBTO_PASS, "bind_ip": "on",
                                             "Submit": ".%3AEinloggen%3A.", "ret_url": ""})

        url = "http://nzb.to/?p=list&cat=13&sa_Video-Genre=3221225407&sort=post_date&order=desc&amount=100"

        urlArgs = {'q': '',
                   "rpp": 50, #max 50
                  "ns": 1, #nospam
                  "szs":16, #min 100MB
                  "sp":1 #nopass
                  }

        #url += urllib.urlencode(urlArgs)

        logger.log(u"NZBto cache update URL: " + url, logger.DEBUG)

        data = self.provider._doSearch("cache")
        if not data:
            return

        #logger.log(u"{0}".format(data))
        self.setLastUpdate()

        # now that we've got the latest releases lets delete the old cache
        logger.log(u"Clearing nzb.to cache and updating with new information")
        self._clearCache()

        for item in data:
            self._parseItem(item)


class NZBDownloader(object):
    def __init__(self, provider_result, session):
        self.provider_result = provider_result
        self._session = session
        self.fetched = False
        self._name = ''
        self._content = ''
        self._password = ''

    @property
    def name(self):
        if not self.fetched:
            self.download()
        return self._name

    @property
    def content(self):
        if not self.fetched:
            self.download()
        return self._content

    def download(self):
        """
        Download nzb file for search result. Nzb.to does not provide a api key service,
        so we have to prefetch all nzb files. The filename format is: "name {{ password }}.nzb",
        where the password is optional. If a password is provided we extract and save it to our result.
        So Sickbeard recognizes the episode we remove the nzb.to file prefixes.
        """
        self.fetched = True
        req = self._session.get(self.provider_result.url)
        _, params = cgi.parse_header(req.headers.get('Content-Disposition', ''))
        filename = os.path.splitext(params['filename'])[0]
        logger.log('Downloaded nzb from nzb.to: "%s"' % filename, logger.DEBUG)

        if filename.startswith('TV_'):
            filename = filename[3:]

        match = re.search('(.*)\{\{(.*)\}\}', filename)
        self.provider_result.extraInfo = [req.content]

        if match:
            self._name = match.group(1)
            self._password = match.group(2)
            #if there is a password, append it to the nzb file as meta tag... supported by sab > 0.7.8 AND nzbget 11
            ElementTree.register_namespace("", "http://www.newzbin.com/DTD/2003/nzb")
            root = ElementTree.fromstring(req.content)
            if not root.find("{http://www.newzbin.com/DTD/2003/nzb}head"):
                head = ElementTree.SubElement(root, "head")
                meta = ElementTree.SubElement(head, "meta", type="password")
                meta.text = self._password
                self._content = ElementTree.tostring(root)
            else:
                logger.log('Can\'t add password to nzb file: "%s"' % filename, logger.ERROR)
        else:
            self._name = filename
            self._content = req.content

provider = NZBto()
