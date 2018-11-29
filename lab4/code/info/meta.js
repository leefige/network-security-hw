var metaportal = {

	// 默认配置，可以通过loadMetaPotal(cfg)方法override
	config : {
		// 0 - 未登�?; 1 - 已登录；
		mode : 0,
		// 装载Metaportal的HTML元素id，默认为: <div id="header"></div>
		targetHTMLElementId : 'header',
		defaultTabNum : 5,
		htmlCache : null,
		jsonCache : null,
		// 默认�? null; 站点地图、搜索等页面�? "none"
		forceFocusedId : null,
		// Banner左上角显示的系统名称，默认�? "信息门户"
		systemName : '信息门户'
	},

	metaportal_path : {
		"0" : "/f/nav?js=1&auth=false",
		"1" : "/f/nav?js=1&auth=true"
	},

	// 调用Metaportal的入口函�?
	loadMetaPotal : function(cfg) {
		$.ajaxSetup({
			cache : false
		});
		$.extend(this.config, cfg);
		switch (this.config.mode) {
		/*
		 * case 0: getMetaPotal(metaPortalBaseUrl + metaportal_path[mode]);
		 * break; case 1: roamIntoMetaPotal(config.roamUrl, metaPortalBaseUrl +
		 * metaportal_path[mode]); break;
		 */
		default:
			this.getMetaPotal(metaPortalBaseUrl
					+ this.metaportal_path[this.config.mode]);
		}
	},

	getMetaPotal : function(metaPortalUrl) {

		this.attachDependencies();

		if (this.config.htmlCache == null) {
			$.ajax({
				type : 'GET',
				url : metaPortalUrl,
				dataType : 'jsonp',
				jsonp : 'cbf',
				jsonpCallback : 'cb',
				success : function(escapedHtml) {
					metaportal.config.htmlCache = escapedHtml;
					metaportal.onHtmlReady(metaportal.config.htmlCache);
				},
				error : function(e) {
				}
			});
		} else {
			this.onHtmlReady(metaportal.config.htmlCache);
		}

	},

	onHtmlReady : function(htmlCache) {
		metaportal.appendHeader(htmlCache);
		if (metaportal.config.mode == 1) {
			metaportal.fillInfoMenu();
		} else {
			metaportal.showPage();
		}
	},

	// 填充静态HTML部分
	appendHeader : function(htmlCache) {
		$('#' + this.config.targetHTMLElementId).html(unescape(htmlCache));

		// systemName
		$('.hot_nav_r .ml10').text(metaportal.config.systemName);
	},

	fillInfoMenu : function() {
		var json = {};

		if (this.config.jsonCache == null) {
			$.getJSON('/__service__/nav.json', function(navJson) {
				json.nav = navJson;
				metaportal.config.jsonCache = JSON.stringify(json);
				metaportal.onJsonReady(metaportal.config.jsonCache);
				metaportal.writeCache(metaportal.config.htmlCache,
						metaportal.config.jsonCache);
			});
		} else {
			this.onJsonReady(this.config.jsonCache);
		}
	},

	onJsonReady : function(jsonCache) {
		var json = $.parseJSON(jsonCache);
		var data = json.nav;

		/* Tabs */
		var tabNum = data.config.tabNum;
		if (!tabNum) {
			tabNum = metaportal.config.defaultTabNum;
		}
		metaportal.fillTabs(data.menu, tabNum);

		/* User Info */
		$(".hot_nav_right #userXm").text(data.config.userInfo.userName);
		$(".hot_nav_right #userZjh").text(data.config.userInfo.zjh);
		$(".hot_nav_right #userYhm").text(data.config.userInfo.yhm);

		/* Admin */
		var adminItems = data.admin;
		if ((data.config.userInfo.isAdmin === 'N' && data.config.userInfo.isSuperAdmin === 'N')
				|| !adminItems || adminItems.length == 0) {
			// Do nothing
		} else {
			$('#wt2service').show();
			$.each(adminItems, function(index, item) {
				var p = $('#servicename').append(
						'<p><a href="' + item.url + '" >' + item.name
								+ '</a></p>');
			});

			$("#wt2service").hover(function() {
				$("#servicenameShow").show();
			}, function() {
				$("#servicenameShow").hide();
			})
		}

		metaportal.showPage();
	},

	showPage : function() {
		$('body').show();
	},

	writeCache : function(htmlCache, jsonCache) {
		$.ajax({
			type : "POST",
			url : "/__metaportalcache__",
			data : {
				"metaportal_global_nav_html" : htmlCache,
				"metaportal_business_nav_callback_params_json" : jsonCache,
				"metaportal_business_nav_callback_params_url" : ""
			}
		});
	},

	/* ---------- Utils ---------- */

	// 此方法暂时不�?
	roamIntoMetaPotal : function(roamUrl, metaPortalUrl) {
		$('<iframe>', {
			id : 'roam_into_meta_portal',
			src : roamUrl,
			load : function() {
				metaportal.getMetaPotal(metaPortalUrl);
			},
			width : '0',
			height : '0',
			marginwidth : '0',
			marginheight : '0'
		}).css('border-style', 'none').appendTo('body');
	},

	preload : function() {
	},

	onload : function() {
	},

	attachDependencies : function() {
		$('head').append(
				'<link rel="stylesheet" href="' + metaPortalBaseUrl
						+ '/site/css/style.css" type="text/css" />');
		$('head').append(
				'<link rel="stylesheet" href="' + metaPortalBaseUrl
						+ '/site/css/common.css" type="text/css" />');
		$('head').append(
				'<link rel="stylesheet" href="' + metaPortalBaseUrl
						+ '/site/css/jquery-ui.css" type="text/css" />');
		$('head').append(
				'<link rel="stylesheet" href="' + metaPortalBaseUrl
						+ '/site/css/menu.css" type="text/css" />');
		$('head').append(
				'<link rel="stylesheet" href="' + metaPortalBaseUrl
						+ '/site/css/page.css" type="text/css" />');
		$('head').append(
				'<link rel="stylesheet" href="' + metaPortalBaseUrl
						+ '/site/css/sdmenu.css" type="text/css" />');
		$('head').append(
				'<link rel="stylesheet" href="' + metaPortalBaseUrl
						+ '/site/css/style_accordion.css" type="text/css" />');
	},

	fillTabs : function(menu, tabNum) {
		if (!menu || menu.length == 0) {
			return;
		}

		/*
		 * Determine Focused Tab
		 * 
		 * 1. config[forceFocusedId] != null: Use config[forceFocusedId]
		 * 
		 * 2. URL[_meta_focusedId] does not exist: Use menu[focused=true]
		 * 
		 * 3. URL[_meta_focusedId] == "none": No focused tab
		 * 
		 * 4. Use URL[_meta_focusedId]
		 * 
		 */
		var useMenuFocused = false;
		var focusedId = metaportal.config.forceFocusedId;
		if (focusedId == null) {
			focusedId = metaportal.getUrlParam("_meta_focusedId");
		}
		if (focusedId == null) {
			useMenuFocused = true;
		}

		/* Append URL params & assign 'metaFocused' & Remove hidden tabs */
		var tabIndicesToDelete = [];
		$.each(menu, function(index, tab) {
			metaportal.appendMetaUrlParams(tab);

			if (useMenuFocused && tab.focused) {
				tab.metaFocused = true;
			} else if (focusedId == tab.id) {
				tab.metaFocused = true;
			}

			if (tab.hide) {
				if (tab.userService) {
					var $li = $('#wt2userservice');
					if ($li) {
						$li.find('a').attr('href', tab.url);
						$li.show();
					}
				}
				tabIndicesToDelete.push(index);
			}
		});
		$.each(tabIndicesToDelete, function(index, value) {
			menu.splice(value, 1);
		});

		/* Render tabs */
		var length = menu.length;
		var $tabs = $(".hot_nav_left");
		var $more = $tabs.children('#more');
		var i, tab;
		for (i = 0; i < Math.min(tabNum, length); i++) {
			tab = menu[i];
			if (tab.metaFocused) {
				$('<li><a class="cur">' + tab.name + '</a></li>').insertBefore(
						$more);
			} else {
				$('<li><a href="' + tab.url + '">' + tab.name + '</a></li>')
						.insertBefore($more);
			}
		}
		// 更多
		if (length > tabNum) {
			var $moreContent = $more.children('#more_content_nav');
			var perLine = 4, count = 0;
			var $p = $('<p>');
			$moreContent.append($p);
			var $a;
			for (i = tabNum; i < length; i++) {
				tab = menu[i];
				$a = $('<a>');
				$a.attr('href', tab.url);
				$a.html(tab.name);
				$p.append($a);
				count++;
				if (count % perLine == 0) {
					$a.addClass('none_bg');
					$p = $('<p>');
					$moreContent.append($p);
				}

				/* tab swap */
				if (tab.metaFocused) {
					var $li = $tabs.children('li:nth-child(' + tabNum + ')');
					var $liA = $li.children('a')
					var tempHref = $liA.attr('href');
					var tempText = $liA.html();
					$liA.attr('href', '#');
					$liA.html($a.html());
					$liA.addClass('cur');
					$a.attr('href', tempHref);
					$a.html(tempText);
				}

			}
			$p.children('a').last().addClass('none_bg');
			$more.show();
		}
	},

	// _meta_focusedId ("none": 特殊页面)
	appendMetaUrlParams : function(tab) {
		if (!tab.id || !tab.url) {
			return;
		}
		var focusedId = tab.id;
		if (tab.hide || tab.userService) {
			focusedId = "none";
		}
		if (tab.url.indexOf("?") == -1) {
			tab.url += "?_meta_focusedId=" + focusedId;
		} else {
			tab.url += "&_meta_focusedId=" + focusedId;
		}
	},

	getUrlParam : function(sParam) {
		var sPageURL = window.location.search.substring(1);
		var sURLVariables = sPageURL.split('&');
		for (var i = 0; i < sURLVariables.length; i++) {
			var sParameterName = sURLVariables[i].split('=');
			if (sParameterName[0] == sParam) {
				return sParameterName[1];
			}
		}
		return null;
	}

};