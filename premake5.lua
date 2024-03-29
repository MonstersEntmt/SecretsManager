workspace("SecretsManager")
	common:addConfigs()
	common:addBuildDefines()

	cppdialect("C++latest")
	rtti("Off")
	exceptionhandling("On")
	flags("MultiProcessorCompile")

	startproject("CLI")
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

		pkgdeps({ "commonbuild", "backtrace" })

		common:addActions()

	project("IPC")
		location("IPC/")
		warnings("Extra")

		kind("StaticLib")
		common:outDirs(true)

		includedirs({ "%{prj.location}/Inc/" })
		files({
			"%{prj.location}/Inc/**",
			"%{prj.location}/Src/**"
		})
		removefiles({ "*.DS_Store" })

		pkgdeps({ "commonbuild", "backtrace" })

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
			"%{wks.location}/IPC/Inc/"
		})
		links({
			"SecretsLib",
			"IPC"
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
		externalincludedirs({ "%{wks.location}/IPC/Inc/" })
		links({ "IPC" })

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
		externalincludedirs({ "%{wks.location}/IPC/Inc/" })
		links({ "IPC" })

		common:addActions()