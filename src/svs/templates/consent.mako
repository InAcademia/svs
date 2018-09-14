<!DOCTYPE html>
<html>
<head>
    <title>${_("Consent")}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="content-type" content="text/html;" charset="utf-8"/>

    <!-- Latest compiled and minified CSS -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css">
    <link rel="stylesheet" href="/consent.css">

    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
    <style>
    /* Space out content a bit */
body {
  padding-top: 20px;
  padding-bottom: 20px;
    overflow-y: scroll;
}

/* Everything but the jumbotron gets side spacing for mobile first views */

.header,
.marketing,
.footer {
  padding-left: 0px;
  padding-right: 0px;
}

/* Custom page header */
.header {
  padding-bottom: 4px;
  border-bottom: 1px solid #e5e5e5;
}
/* Make the masthead heading the same height as the navigation */
.header h3 {
  margin-top: 0;
  margin-bottom: 0;
  line-height: 40px;
  padding-bottom: 19px;
}

.content h1, h2, h3 {
  margin-top: 0;
  margin-bottom: 0;
  line-height: 40px;
  padding-bottom: 19px;
}

/* Custom page footer */
.footer {
  margin-top: 30px;
  padding-top: 20px;
  color: #777;
  /* border-top: 1px solid #f8f8f8; */
  background-color: #f8f8f8;
}

/* Customize container */
@media (min-width: 768px) {
  .container {
    max-width: 730px;
  }
}
.container-narrow > hr {
  margin: 30px 0;
}

/* Main marketing message and sign up button */
.jumbotron {
  text-align: center;
  border-bottom: 1px solid #e5e5e5;
}
.jumbotron .btn {
  font-size: 21px;
  padding: 14px 24px;
}

/* Supporting marketing content */
.marketing {
  margin: 40px 0;
}
.marketing p + h4 {
  margin-top: 28px;
}

/* Responsive: Portrait tablets and up */
@media screen and (min-width: 768px) {
  /* Remove the padding we set earlier */
  .header,
  .marketing,
  .footer {
    padding-left: 0;
    padding-right: 0;
  }
  /* Space out the masthead */
  .header {
    margin-bottom: 30px;
  }
  /* Remove the bottom border on the jumbotron for visual effect */
  .jumbotron {
    border-bottom: 0;
  }
}

@media (max-width: 768px) {
  .btn-responsive {
    padding: 6px 8px;
    margin-bottom: 10px;
    font-size:90%;
    line-height: 1.2;
    width: 100%;
    border-radius:3px;
  }
}

@media (min-width: 769px) and (max-width: 992px) {
  .btn-responsive {
    padding:4px 9px;
    font-size:90%;
    line-height: 1.2;
  }
}

.top {
    vertical-align: top;
}

.table-wrapper {
    overflow-x: auto;
    overflow-y: auto;
    font-size: small;
}
.inline li {
    display: inline;
}

#remember-message { margin-top: 20px; }
#remember-message form { margin-bottom: 2px; }

.navbar {
   margin-bottom: 30px;
}

@-webkit-viewport   { width: device-width; }
@-moz-viewport      { width: device-width; }
@-ms-viewport       { width: device-width; }
@-o-viewport        { width: device-width; }
@viewport           { width: device-width; }

#map_canvas { width: 100%; height: 350px; }
#map_canvas img { max-width: none; }

.google-map-canvas,.google-map-canvas * { box-sizing:content-box; }

.twitter-typeahead { width: 100%; }

.idp-description { width: 65%; }

.idp-icon { max-width: 29%; max-height: 50px; margin-right: 5%; margin-top: -3%; width: auto; }

.sp-description { max-width: 75%; }
.sp-icon { width: auto; margin-bottom:5px;}
.sp-thumbnail {width: 100px; margin: 0 0; padding-left: 5px;}

.idselect { width: 100%; }

.img-small {
    max-height: 50px;
}

.cpstats td, th { font-size: x-small; }

pre.prettyprint {
    display: block;
    overflow: auto;
    width: auto;
    /* max-height: 600px; */
    white-space: pre;
    word-wrap: normal;
    padding: 10px;
    font-size: x-small;
}

.logo {
    max-height: 100px;
    margin-bottom: 1em;
}

.fallback {
    display: none;
}

span.select:hover, span.proceed:hover {
    background-color: lightgrey !important;
}

.wide { width: 100%; display: block; }

.vertical-align {
    display: flex;
    align-items: center;
}

#sp-icon-container {
    max-width: 20% !important;
    min-width: 0px;
}

#sp-title-container {
    max-width: 80%;
    vertical-align: middle;
}



.fa-spin { -webkit-filter: blur(0); }

h5.sp {
    margin-bottom: 1px;
    padding-bottom: 0px;
}

h3.sp {
    margin-bottom: 1px;
    padding-bottom: 0px;
}

#sp-col-2
{
  max-width: 17%;
}

.requester_logo
{
  width:100%;
}



    </style>
</head>
<body>

<div class="container">
  <div class="header text-muted">
    <div class="row">
        <div class="col-xs-10 sp-icon-container logo">
        <img src="data:image/png;base64,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
">
      </div>
      <!-- Language selection -->
      <div class="col-xs-2 align-right sp-col-2">
        <form action="${form_action}" method="GET">
          <select name="lang" id="lang" onchange="this.form.submit()">
              <option value="en">English</option>
              <option value="sv">Swedish</option>
              <option value="af">Afrikaans</option>
              <option value="cs">Czech</option>
              <option value="da">Danish</option>
              <option value="de">German</option>
              <option value="el">Greek</option>
              <option value="et">Estonian</option>
              <option value="fr">French</option>
              <option value="hu">Hungarian</option>
              <option value="lt">Lithuanian</option>
              <option value="nl">Dutch</option>
              <option value="pt">Portuguese</option>
              <option value="ru">Russian</option>
          </select>
        </form>
      </div>
    </div>
    <div class="row col-md-12 sp-title-container">
      <h3 class="sp">${_("Your consent is required to continue.")}</h3>
    </div>
    <div class="row clearfix"></div>
  </div>
  <div class="row">&nbsp;</div>
  <div class="clearfix">&nbsp;</div>



<div class="row">
    <div class="col-md-10">
        <p class="text-justify">${_("To allow you to prove your affiliation, ")} ${requester_name} ${_("makes use of the InAcademia service.")}</p>
        <p class="text-justify">${_("Your institution has confirmed your affiliation to Inacademia. We now ask you to consent to confirming your affiliation to ")} ${requester_name}. ${_("In addition, InAcademia may reveal the country and name of your institution. InAcademia will not store any of the data we have received from your institution, nor will we store your consent.")}</p>
        <p class="text-justify"><b>${_('In order to exercise your data subject rights, please save this screen (e.g. make a print screen). It shall be provided with your request.')}</b></p>
        <p class="text-justify">${_("For more details on the information we will provide to")} ${requester_name}, ${_('please select "Details" below.')}</p>
  </div>
  <div class="col-md-2 aligh-right sp-col-2">
      % if requester_logo:
      <img id="requester_logo" class="requester_logo" src="${requester_logo}"/>
      % endif
  </div>
</div>
<div class="row">
     <div class="col-md-10">${_("More information: ")}<a href="https://inacademia.org/privacy-and-data-protection/">${_("Privacy Statement")}</a></div>
 </div>
</div>
<div class="row clearfix"><br/></div>
<div class="panel-group">
    <div class="panel panel-default">
        <div class="panel-heading">
            <a data-toggle="collapse" data-target="#attributeDetails" aria-expanded="false" aria-controls="attributeDetails"><h4 class="panel-title">${_("Details")}</h4></a>
        </div>
        <div class="panel-collapse collapse" id="attributeDetails">
             <ul class="list-group">
             % for attribute in released_claims:
                 <li class="list-group-item"><span>${_(attribute).capitalize()}</span>:&nbsp;
                 <span>
                 % if isinstance(released_claims[attribute], list):
                     % for v in set(released_claims[attribute]):
                         ${v}
                     % endfor
                 % else:
                     ${released_claims[attribute]}
                 % endif
                 </span></li>
             % endfor
             </ul>
        </div>
    </div>
</div>
    <div class="row"><hr/></div>

    <div class="row clearfix"><br/></div>
    <div class="btn-block">
    <form name="allow_consent" id="allow_consent_form" method="GET">
      <input name="Yes" value="${_('OK, accept')}" id="submit_ok" formaction="${form_action}/allow" 
             type="submit" class="btn btn-primary">
      <input name="No" value="${_('No, cancel')}" id="submit_deny" formaction="${form_action}/deny" 
             type="submit" class="btn btn-warning">
    </form>
    </div>
</div>
 <footer></footer>
</div>

<script type="application/javascript">
    $("form input[type=submit]").click(function () {
        $("input[type=submit]", $(this).parents("form")).removeAttr("clicked");
        $(this).attr("clicked", "true");
    });

    function setSelectedIndex(s, v) {
        for ( var i = 0; i < s.options.length; i++ ) {
            if ( s.options[i].value == v ) {
                s.options[i].selected = true;
                return;
            }
        }
    }

    window.onload = function ()
    {
         setSelectedIndex(document.getElementById('lang'), "${language}");
    };

</script>
</body>
</html>
