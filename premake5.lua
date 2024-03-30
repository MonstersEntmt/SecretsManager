workspace("SecretsManager")
	common:addConfigs()
	common:addBuildDefines()

	cppdialect("C++latest")
	rtti("Off")
	exceptionhandling("On")
	flags("MultiProcessorCompile")

	startproject("CLI")
	project("Networking")
		location("Networking/")
		warnings("Extra")

		kind("StaticLib")
		common:outDirs(true)

		includedirs({ "%{prj.location}/Inc/" })
		files({
			"%{prj.location}/Inc/**",
			"%{prj.location}/Src/**"
		})
		removefiles({ "*.DS_Store" })

		pkgdeps({ "commonbuild" })

		filter("system:windows")
			links({ "Ws2_32.lib" })
		filter({})

		common:addActions()

	project("SecretsLib")
		location("SecretsLib/")
		warnings("Extra")

		kind("StaticLib")
		common:outDirs(true)

		includedirs({ "%{prj.location}/Inc/" })
		files({
			"%{prj.location}/Inc/**",
			"%{prj.location}/Src/**"
		})
		removefiles({ "*.DS_Store" })

		pkgdeps({ "commonbuild" })
		externalincludedirs({ "%{wks.location}/Networking/Inc/" })
		links({ "Networking" })

		common:addActions()

	project("Daemon")
		location("Daemon/")
		warnings("Extra")

		kind("ConsoleApp")
		common:outDirs()
		common:debugDir()

		includedirs({ "%{prj.location}/Src/" })
		files({ "%{prj.location}/Src/**" })
		removefiles({ "*.DS_Store" })

		pkgdeps({ "commonbuild", "backtrace" })
		externalincludedirs({
			"%{wks.location}/SecretsLib/Inc/",
			"%{wks.location}/Networking/Inc/"
		})
		links({
			"SecretsLib",
			"Networking"
		})

		common:addActions()

	project("CLI")
		location("CLI/")
		warnings("Extra")

		kind("ConsoleApp")
		common:outDirs()
		common:debugDir()

		includedirs({ "%{prj.location}/Src/" })
		files({ "%{prj.location}/Src/**" })
		removefiles({ "*.DS_Store" })

		pkgdeps({ "commonbuild", "backtrace" })
		externalincludedirs({ "%{wks.location}/Networking/Inc/" })
		links({ "Networking" })

		common:addActions()

	project("BrowserExt")
		location("BrowserExt/")
		warnings("Extra")

		kind("ConsoleApp")
		common:outDirs()
		common:debugDir()

		includedirs({ "%{prj.location}/Src/" })
		files({ "%{prj.location}/Src/**" })
		removefiles({ "*.DS_Store" })

		pkgdeps({ "commonbuild", "backtrace" })
		externalincludedirs({ "%{wks.location}/Networking/Inc/" })
		links({ "Networking" })

		common:addActions()