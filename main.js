/**
 * A set of tools for exploring UPNP devices
 * This reference was used to understand the communications of these devices:
 * http://www.upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0-20080424.pdf
 */

/* jshint esnext:true, debug:true */

function getJSON(path, callback, error) {
  "use strict";
  var xhr = new XMLHttpRequest();
  xhr.open("GET", path);
  xhr.setRequestHeader("Accept", "application/json");
  xhr.onloadend = function() {
    if (xhr.status >= 200 && xhr.status < 400) {
      if (callback && typeof callback === "function") {
        callback(JSON.parse(xhr.responseText));
      }
    } else {
      if (error && typeof error === "function") {
        error(xhr.status, xhr.responseText);
      }
    }
  };
  xhr.send();
}
/** Stream chunked line oriented JSON message from the server */
function streamJSON(path, headers, onMessage, onError) {
  "use strict";
  if (typeof headers === "function") {
    // shift params
    onError = onMessage;
    onMessage = headers;
    headers = undefined;
  }
  var xhr = new XMLHttpRequest();
  xhr.open("GET", path);
  xhr.setRequestHeader("Accept", "application/x-json-stream");
  if (typeof headers === "object") {
    for (let k in headers) {
      xhr.setRequestHeader(k, headers[k]);
    }
  }
  var read = 0;
  xhr.onload = function(e) {
    if (xhr.status >= 400) {
      if (onError && typeof onError === "function") {
        onError(xhr.status, xhr.responseText);
      } else {
        console.error(xhr.responseText);
      }
    }
  };
  xhr.onprogress = xhr.onloadend = function(e) {
    if (xhr.status >= 200 && xhr.status < 400) {
      console.log("progress/loadend: loaded=" + e.loaded);
      if (e.loaded > read) {
        // continue from where we left off
        let svcsTxt = xhr.responseText
          .slice(read)
          .split(/\r?\n/)
          .filter(t => t.length);
        let svcs = svcsTxt.map(JSON.parse);
        svcs.forEach(onMessage);
        read = e.loaded;
      }
    }
  };
  xhr.send();
}

function getXML(path, callback, onError) {
  "use strict";
  var xhr = new XMLHttpRequest();
  xhr.open("GET", path);
  xhr.setRequestHeader("Accept", "text/xml");
  xhr.onload = function(e) {
    if (xhr.status >= 200 && xhr.status < 400) {
      callback(xhr.responseXML);
    } else {
      if (typeof onError === "function") {
        onError(xhr.status, xhr.responseText);
      }
    }
  };
  xhr.send();
}
function postXML(path, headers, data, callback, onError) {
  "use strict";
  var xhr = new XMLHttpRequest();
  xhr.open("POST", path);
  xhr.setRequestHeader("Accept", "text/xml");
  xhr.setRequestHeader("Content-Type", "text/xml; charset=utf-8");
  for (let k in headers) {
    xhr.setRequestHeader(k, headers[k]);
  }
  xhr.onload = function(e) {
    if (xhr.status >= 200 && xhr.status < 400) {
      callback(xhr.responseXML);
    } else {
      if (typeof onError === "function") {
        onError(xhr.status, xhr.responseText);
      }
    }
  };
  xhr.send(data);
}

function xml2js(xml) {
  "use strict";
  if (xml.nodeType === Node.ELEMENT_NODE) {
    // element
    let obj = {};
    if (xml.attributes.length > 0) {
      obj["@attributes"] = {};
      for (let a of xml.attributes) {
        obj["@attributes"][a.nodeName] = a.nodeValue;
      }
    }
    if (xml.hasChildNodes()) {
      if (
        xml.firstChild === xml.lastChild &&
        xml.firstChild.nodeType === Node.TEXT_NODE
      ) {
        return xml.firstChild.nodeValue;
      }
      if (xml.nodeName.endsWith("List")) {
        /* recognise an array like
         * <serviceList><service/><service/></serviceList>
         */
        let isList = true;
        for (let child of xml.children) {
          if (child.nodeName + "List" !== xml.nodeName) isList = false;
        }
        if (isList) {
          return [].map.call(xml.children, xml2js);
        }
      }
      for (let item of xml.children) {
        let nodeName = item.nodeName;
        if (typeof obj[nodeName] === "undefined") {
          obj[nodeName] = xml2js(item);
        } else if (typeof obj[nodeName].push === "undefined") {
          obj[nodeName] = [obj[nodeName], xml2js(item)];
        } else {
          obj[nodeName].push(xml2js(item));
        }
      }
    }
    return obj;
  } else if (xml.nodeType === Node.TEXT_NODE) {
    return xml.nodeValue.replace(/^\s+|\s+$/g, "");
  }
}

(function(window, document, undefined) {
  "use strict";
  /* Utility functions etc */
  let $ = document.querySelector.bind(document);
  let $$ = document.querySelectorAll.bind(document);
  let isArray = x => x && {}.toString.call(x) === "[object Array]";
  let isPlainObject = x => x && {}.toString.call(x) === "[object Object]";
  function str2node(str) {
    var div = document.createElement("div");
    div.innerHTML = str;
    return div.firstChild;
  }
  /** Escape a foreign value that is going to be put in an attribute */
  var esc = (function() {
    var alpha = new Int8Array(256);
    for (let c of "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") {
      alpha[c.codePointAt(0)] = 1;
    }
    return function esc(strs, ...exps) {
      var result = strs[0];
      strs = strs.slice(1);
      for (let i = 0; i < strs.length; i++) {
        // escape exp[i]
        let escaped = "";
        {
          let exp = exps[i];
          for (let j = 0; j < exp.length; j++) {
            let cp = exp.codePointAt(j);
            if (cp > 255 || alpha[cp]) {
              escaped += exp.charAt(j);
            } else {
              escaped += "&#x" + cp.toString(16) + ";";
            }
          }
        }
        result += escaped + strs[i];
      }
      return result;
    };
  })();
  function findParent(element, selector) {
    for (let p = element; p != document.documentElement; p = p.parentNode) {
      if (p.matches(selector)) {
        return p;
      }
    }
  }

  /* Our model of the world */

  let model = {
    detailed: false,
    notifications: {
      enabled: true,
      maxItems: 30,
      items: []
    },
    services: [],
    svcLookup: Object.create(null)
  };

  let notificationSource = new EventSource("/api/notifications");

  /* Rendering Functions */

  function renderService(svc) {
    var headers = svc.headers;
    var result = esc`<li class=service id="${headers.USN}">`;
    result += "<dl class=service-headers>";
    for (let k in headers) {
      if (model.detailed || (k !== "CACHE-CONTROL" && k !== "DATE")) {
        result += esc`<dt>${k}</dt>`;
        if (headers[k] === "") {
          result += "<dd>&nbsp;</dd>";
        } else {
          result += esc`<dd>${headers[k]}</dd>`;
        }
      }
    }
    result += "</dl>";
    result += esc`<button type=button class=btn-desc data-usn="${
      headers.USN
    }">Describe</button>`;
    result += "<div class=svc-desc-container></div>";
    result += "<div class=svc-list-container></div>";
    result += "</li>";
    return result;
  }

  function renderServiceDescription(desc) {
    var result = "<dl class=service-description>";
    for (let k in desc) {
      if (typeof desc[k] === "string" && k.indexOf(":") === -1) {
        result += esc`<dt>${k}</dt>`;
        result += esc`<dd>${desc[k]}</dd>`;
      }
    }
    result += "</dl>";
    return result;
  }

  function renderServiceList(serviceList) {
    var result = "<ul>";
    for (let service of serviceList) {
      result += esc`<li data-service-id="${service.serviceId}"
                        data-service-type="${service.serviceType}">`;
      result += "<dl class=soap-service>";
      for (let k in service) {
        result += esc`<dt>${k}</dt>`;
        result += esc`<dd>${service[k]}`;
        if (k === "SCPDURL") {
          result += esc` <button type=button
                                 class=btn-methods
                                 data-url="${service[k]}"
                                 data-service-id="${service.serviceId}"
                         >Show Methods</button>`;
          // TODO: implement this and add ability to Query and Subsribe to
          // state variables
          result += esc` <button type=button
                                 disabled
                                 class=btn-state-vars
                                 data-url="${service[k]}"
                                 data-service-id="${service.serviceId}"
                         >Show State Variables</button>`;
        }
        result += "</dd>";
      }
      result += "</dl>";
      result += esc`<div class=methods-container data-control="${
        service.controlURL
      }"></div>`;
      result += "</li>";
    }
    return result + "</ul>";
  }

  function renderMethods(scpd) {
    var result = "<ul>";
    for (let action of scpd.actions) {
      result += esc`<li name="${action.name}">`;
      result += "<form>";
      result += esc`<strong>${action.name}</strong>`;
      if (action.arguments) {
        for (let argument of action.arguments) {
          result += "<div>";
          result += esc`<span class=argument-direction>${
            argument.direction
          }</span>`;
          result += esc`<label class=argument-label for="${argument.name}">${
            argument.name
          }</label>`;

          let stateVar = scpd.stateVariables[argument.relatedStateVariable];
          if (argument.direction === "in" && stateVar.allowedValues) {
            let select = document.createElement("select");
            select.className = "method-argument";
            select.name = select.title = argument.name;
            select.dataset.direction = argument.direction;
            select.dataset.relatedStateVariable = argument.relatedStateVariable;
            select.innerHTML += stateVar.allowedValues
              .map(v => esc`<option>${v}</option>`)
              .join("");
            result += select.outerHTML;
          } else {
            // TODO: use the state variable data type to restrict input e.g. ui4
            // restrict to numbers
            let input = document.createElement("input");
            if (
              [
                "ui1",
                "ui2",
                "ui4",
                "i1",
                "i2",
                "i4",
                "int",
                "r4",
                "r8",
                "number"
              ].includes(stateVar.dataType)
            ) {
              input.type = "number";
            } else if (stateVar.dataType === "boolean") {
              input.type = "range";
              input.value = "0";
              input.max = 1;
              input.min = 0;
            } else {
              input.type = "text";
            }
            input.className = "method-argument";
            input.name = input.title = input.placeholder = argument.name;
            if (argument.direction === "out") {
              input.readOnly = true;
            }
            input.dataset.direction = argument.direction;
            input.dataset.relatedStateVariable = argument.relatedStateVariable;
            result += input.outerHTML;
          }
          result += "</div>";
        }
      }
      result += esc`<button type=button class=btn-send data-action="${
        action.name
      }">Send</button>`;
      result += "</form>";
      result += "</li>";
    }
    return result;
  }

  function renderNotification(headers) {
    var result = "<li class=notification>";
    // important properties
    result += "<div class=notification-main>";

    // Can get mixed case, so create version with uppercase only
    var upHeaders = {};
    for (let k in headers) {
      upHeaders[k.toUpperCase()] = headers[k];
    }

    if ("LOCATION" in upHeaders) {
      let url = new URL(upHeaders.LOCATION);
      result += esc`<span title="host">${url.host}</span>`;
    }
    if ("NTS" in upHeaders) {
      result += esc`<span title="NTS">${upHeaders.NTS}</span>`;
    }
    if ("ST" in upHeaders) {
      result += esc`<span title="ST"><small>${upHeaders.ST}</small></span>`;
    }
    if ("NT" in upHeaders) {
      result += "<br>";
      result += esc`<span title="NT"><small>${upHeaders.NT}</small></span>`;
    }
    result += "</div>";
    result += '<dl class="notification-extra hidden">';
    //result += '<dl class="notification-extra">';
    for (let k in headers) {
      result += esc`<dt>${k}</dt>`;
      result += esc`<dd>${headers[k]}</dd>`;
    }
    result += "</dl>";
    return (result += "</li>");
  }

  $("#btnDiscover").addEventListener("click", function() {
    model.services = [];
    model.svcLookup = Object.create(null);
    $("#hosts").innerHTML = "";
    let st = $("#discover-st").value;
    streamJSON("/api/discover", { ST: st }, function(headers) {
      // Devices may/should notify multiple times, so dedup once we have
      // already seen the USN
      if (!(headers.USN in model.svcLookup)) {
        var svc = { headers };
        model.services.push(svc);
        model.svcLookup[headers.USN] = svc;
        $("#hosts").appendChild(str2node(renderService(svc)));
      }
    });
  });

  $("#hosts").addEventListener("data", function(e) {
    console.log(e);
  });
  $("#hosts").addEventListener("error", function(e) {
    console.log(e);
  });

  $("#hosts").addEventListener("click", function(e) {
    if (e.target.classList.contains("btn-desc")) {
      let usn = e.target.dataset.usn;
      let svc = model.svcLookup[usn];
      // have the web server get further info from the LOCATION given
      getXML(
        "/api/description?location=" + encodeURIComponent(svc.headers.LOCATION),
        function(doc) {
          // TODO: consider firing a new event against the element instead of
          // nesting callbacks
          let udn = usn.split("::")[0];
          let udnElems = [].filter.call(
            doc.querySelectorAll("UDN"),
            e => e.textContent === udn
          );
          if (udnElems.length < 1) {
            console.log("could not find matching device in description");
            return;
          }
          let svcRoot = document.getElementById(usn);

          svc.description = {};
          svc.serviceList = [];
          // This device is probably using the same device-UUID for each
          // embedded device. So lets try filtering by deviceType == ST?
          udnElems.forEach((udnElem, idx) => {
            let deviceElem = udnElem.parentNode;
            // convert to javascript object to make manipulation easier
            let description = xml2js(deviceElem);

            if (svc.headers.ST.startsWith("urn:schemas-upnp-org:device")) {
              if (svc.headers.ST === description.deviceType) {
                svc.description = description;
                svc.serviceList = description.serviceList;
              }
            } else if (
              svc.headers.ST.startsWith("urn:schemas-upnp-org:service")
            ) {
              let serviceList = description.serviceList.filter(service => {
                return service.serviceType === svc.headers.ST;
              });

              if (serviceList.length > 0) {
                svc.serviceList = serviceList;
                svc.description = description;
              }
            } else {
              if (udnElems.length > 1) {
                for (let k in description) {
                  svc.description["[" + idx + "]" + k] = description[k];
                }
              } else {
                svc.description = description;
              }
              svc.serviceList = svc.serviceList.concat(description.serviceList);
            }
          });

          // Render device description and service list
          let descNode = svcRoot.querySelector(".svc-desc-container");
          descNode.innerHTML = renderServiceDescription(svc.description);
          let listNode = svcRoot.querySelector(".svc-list-container");
          listNode.innerHTML = renderServiceList(svc.serviceList);
        },
        function(status, err) {
          var errEvent = new Event("error");
          errEvent.data = err;
          e.target.dispatchEvent(errEvent);
          console.error(err);
        }
      );
    } else if (e.target.classList.contains("btn-methods")) {
      let path = e.target.dataset.url;
      let serviceId = e.target.dataset.serviceId;
      let usn = findParent(e.target, "li.service").id;
      let svc = model.svcLookup[usn];
      let locationURL = new URL(svc.headers.LOCATION);
      if (path.includes("?")) {
        locationURL.pathname = path.slice(0, path.indexOf("?"));
        locationURL.search = path.slice(path.indexOf("?"));
      } else {
        locationURL.pathname = path;
      }
      let scpdURL = locationURL.href;
      getXML("/api/scpd?location=" + encodeURIComponent(scpdURL), function(
        doc
      ) {
        var scpd = xml2js(doc.documentElement);
        // process the state variables first
        if (!isArray(scpd.serviceStateTable.stateVariable)) {
          scpd.serviceStateTable.stateVariable = [
            scpd.serviceStateTable.stateVariable
          ];
        }
        // create a lookup of the stateVars by name
        scpd.stateVariables = {};
        for (let sv of scpd.serviceStateTable.stateVariable) {
          if (sv.allowedValueList) {
            sv.allowedValues = sv.allowedValueList;
            delete sv.allowedValueList;
          }
          scpd.stateVariables[sv.name] = sv;
        }

        // make the description a bit nicer to work with
        scpd.actions = scpd.actionList;
        delete scpd.actionList;
        for (let action of scpd.actions) {
          action.arguments = action.argumentList;
          delete action.argumentList;
        }
        let resultElem = document
          .getElementById(usn)
          .querySelector('[data-service-id="' + serviceId + '"]')
          .querySelector(".methods-container");

        resultElem.innerHTML = renderMethods(scpd);
      });
    } else if (e.target.classList.contains("btn-send")) {
      e.target.style.color = "black";
      let action = e.target.dataset.action;
      let serviceType = findParent(e.target, "[data-service-type]").dataset
        .serviceType;
      let SOAPACTION = '"' + serviceType + "#" + action + '"';
      // I can't work out how to get the XMLSerializer to repro the <?xml?>
      // part without including it here
      let doc = new DOMParser().parseFromString(
        '<?xml version="1.0" encoding="utf-8"?>' +
          "<s:Envelope" +
          ' xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"' +
          ' s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"' +
          "/>",
        "text/xml"
      );
      {
        let soapNS = "http://schemas.xmlsoap.org/soap/envelope/";
        let bodyElem = doc.documentElement.appendChild(
          doc.createElementNS(soapNS, "s:Body")
        );
        let methodElem = bodyElem.appendChild(
          doc.createElementNS(serviceType, "u:" + action)
        );
        for (let [k, v] of new FormData(e.target.form)) {
          let argElem = methodElem.appendChild(doc.createElement(k));
          argElem.textContent = v;
        }
      }
      let requestText = new XMLSerializer().serializeToString(doc);

      let usn = findParent(e.target, "li.service").id;
      let svc = model.svcLookup[usn];
      let locationURL = new URL(svc.headers.LOCATION);
      let path = findParent(e.target, "[data-control]").dataset.control;
      let controlURL = locationURL.origin + path;
      postXML(
        "/api/soap?location=" + encodeURIComponent(controlURL),
        { SOAPACTION },
        requestText,
        function(xml) {
          // indicate that we were successful
          e.target.style.color = "green";
          e.target.style.boxShadow = "0 0 5px 1px green";
          window.setTimeout(function() {
            e.target.style.boxShadow = "";
          }, 1000);
          // write response out to form fields
          for (var child of xml.querySelector(action + "Response").children) {
            e.target.form[child.nodeName].value = child.textContent;
          }
        },
        function() {
          e.target.style.color = "red";
          e.target.style.boxShadow = "0 0 5px 1px red";
          window.setTimeout(function() {
            e.target.style.boxShadow = "";
          }, 1000);
        }
      );
    }
    e.stopPropagation();
  });

  $("#notifications-enabled").addEventListener("change", function(e) {
    if (e.target.checked && !model.notifications.enabled) {
      $("#notification-list").style.display = "block";
      model.notifications.enabled = true;
    }
    if (!e.target.checked && model.notifications.enabled) {
      $("#notification-list").style.display = "none";
      model.notifications.enabled = false;
    }
  });

  notificationSource.addEventListener("message", function(e) {
    var notifications = model.notifications;
    var headers = JSON.parse(e.data);
    let nl = $("#notification-list");
    if (notifications.items.length >= notifications.maxItems) {
      notifications.items = notifications.items.slice(1);
      nl.removeChild(nl.lastElementChild);
    }
    notifications.items.push(headers);

    if (nl.firstChild) {
      nl.insertBefore(str2node(renderNotification(headers)), nl.firstChild);
    } else {
      nl.appendChild(str2node(renderNotification(headers)));
    }
  });
})(this, document);
