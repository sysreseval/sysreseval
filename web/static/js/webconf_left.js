// The page the BigBlueButton client lands on after Leave meeting (the logoutURL of the meetings
// the portal creates): inside the iframe of a page of the site, or in the popped-out window.  It
// tells the page that holds it ({t: 'webconf-left', id}: webconf.js removes the iframe and offers
// to rejoin), a popped-out window closes itself, and the Rejoin button loads the join URL again
// in place (a fallback for a holder that does not answer).  No catalog: the texts come from the
// template.

const body = document.body;
const id = body.dataset.webconfId || '';
const holder = window.parent !== window ? window.parent : window.opener;
if (holder) {
  holder.postMessage({t: 'webconf-left', id}, window.location.origin);
}
if (window.opener && window.parent === window) {
  window.close();
}
const rejoin = document.getElementById('webconf-rejoin');
if (rejoin) {
  rejoin.addEventListener('click', () => {
    window.location.assign(body.dataset.joinUrl);
  });
}
