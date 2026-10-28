/* InkBlade documentation site behaviour.
   Progressive enhancement only: no cookies, no storage beyond a language
   preference, no requests to any third party. Pages read fine with JS off. */
(function () {
  "use strict";

  var KEY = "inkblade.lang";
  var root = document.documentElement;

  /* ---------------- language ---------------- */

  function stored() {
    try { return window.localStorage.getItem(KEY); } catch (e) { return null; }
  }

  function remember(lang) {
    try { window.localStorage.setItem(KEY, lang); } catch (e) { /* private mode */ }
  }

  function fromQuery() {
    var m = window.location.search.match(/[?&]lang=(en|zh)\b/);
    return m ? m[1] : null;
  }

  function fromBrowser() {
    var list = navigator.languages || [navigator.language || "en"];
    for (var i = 0; i < list.length; i += 1) {
      var tag = String(list[i]).toLowerCase();
      if (tag.indexOf("zh") === 0) return "zh";
      if (tag.indexOf("en") === 0) return "en";
    }
    return "en";
  }

  function applyLang(lang) {
    root.setAttribute("data-lang", lang);
    root.setAttribute("lang", lang === "zh" ? "zh-Hans" : "en");
    var buttons = document.querySelectorAll("[data-set-lang]");
    for (var i = 0; i < buttons.length; i += 1) {
      var on = buttons[i].getAttribute("data-set-lang") === lang;
      buttons[i].setAttribute("aria-pressed", on ? "true" : "false");
    }
    var t = root.getAttribute(lang === "zh" ? "data-title-zh" : "data-title-en");
    if (t) document.title = t;
    spy();
  }

  function wireLang() {
    var buttons = document.querySelectorAll("[data-set-lang]");
    for (var i = 0; i < buttons.length; i += 1) {
      buttons[i].addEventListener("click", function (ev) {
        var lang = ev.currentTarget.getAttribute("data-set-lang");
        remember(lang);
        applyLang(lang);
      });
    }
    if (buttons.length) applyLang(fromQuery() || stored() || fromBrowser());
    else spy();
  }

  /* ---------------- section spy ---------------- */

  var observer = null;

  function spy() {
    if (!("IntersectionObserver" in window)) return;
    if (observer) observer.disconnect();

    var lang = root.getAttribute("data-lang") || "en";
    var map = {};
    var links = document.querySelectorAll('.rail a[href^="#"], .jump a[href^="#"]');
    for (var i = 0; i < links.length; i += 1) {
      map[links[i].getAttribute("href").slice(1)] = map[links[i].getAttribute("href").slice(1)] || [];
      map[links[i].getAttribute("href").slice(1)].push(links[i]);
    }

    var sections = document.querySelectorAll("section.sec[id]");
    observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        Object.keys(map).forEach(function (id) {
          map[id].forEach(function (link) {
            link.classList.toggle("active", id === entry.target.id);
          });
        });
      });
    }, { rootMargin: "-18% 0px -72% 0px", threshold: 0 });

    for (var j = 0; j < sections.length; j += 1) {
      var blocks = sections[j].querySelectorAll(".lang-block");
      if (!blocks.length || sections[j].querySelector('.lang-block[data-lang="' + lang + '"]')) {
        observer.observe(sections[j]);
      }
    }
  }

  /* ---------------- copy buttons ---------------- */

  function wireCopy() {
    var pres = document.querySelectorAll("pre");
    for (var i = 0; i < pres.length; i += 1) {
      (function (pre) {
        var host = pre.parentNode && pre.parentNode.classList.contains("term") ? pre.parentNode : pre;
        var button = document.createElement("button");
        button.type = "button";
        button.className = "copy";
        button.textContent = "cp";
        button.setAttribute("aria-label", "Copy command");
        button.addEventListener("click", function () {
          var text = (pre.querySelector("code") || pre).textContent || "";
          function done() {
            button.textContent = "ok";
            window.setTimeout(function () { button.textContent = "cp"; }, 1200);
          }
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(done, function () {});
          } else {
            var area = document.createElement("textarea");
            area.value = text;
            area.style.position = "fixed";
            area.style.opacity = "0";
            document.body.appendChild(area);
            area.select();
            try { document.execCommand("copy"); done(); } catch (e) { /* ignore */ }
            document.body.removeChild(area);
          }
        });
        host.appendChild(button);
      })(pres[i]);
    }
  }

  /* ---------------- misc ---------------- */

  function wireYear() {
    var nodes = document.querySelectorAll("[data-year]");
    var year = String(new Date().getFullYear());
    for (var i = 0; i < nodes.length; i += 1) nodes[i].textContent = year;
  }

  document.addEventListener("DOMContentLoaded", function () {
    wireLang();
    wireCopy();
    wireYear();
  });
})();
