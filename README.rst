WebAuthn Authenticator Plugin
=============================

   
.. image:: https://curity.io/assets/images/badges/webauthn-authenticator-quality.svg
       :target: https://curity.io/resources/code-examples/status/
       
.. image:: https://curity.io/assets/images/badges/webauthn-authenticator-availability.svg
       :target: https://curity.io/resources/code-examples/status/
    
This project provides an open source WebAuthn Authenticator plug-in for the Curity Identity Server. This allows an administrator to add functionality to Curity which will then enable end users to login using their physical authenticator devices.

Building the Plugin
~~~~~~~~~~~~~~~~~~~

You can build the plugin by issue the command ``gradlew build``. This will produce a JAR file in the target directory, which can be installed.

Installing the Plugin
~~~~~~~~~~~~~~~~~~~~~

To install the plugin, copy the compiled JAR (and all of its dependencies) into the ``${IDSVR_HOME}/usr/share/plugins/${pluginGroup}`` on each node, including the admin node. For more information about installing plugins, refer to the `curity.io/plugins`_.
Some of the dependencies required by the plugin are already provided by the Curity Identity Server. The additional ones that are not provided and need to be copied together with the plugin are:

* org.apache.commons
* com.google.guava
* com.fasterxml.jackson.core
* com.fasterxml.jackson.dataformat
* org.jose4j

You can find the dependencies jar files in ``build/libs`` after executing the task ``gradlew copyRuntimeLibs``. Note that some of the above dependencies bring in a few extra ones.

Creating a WebAuthn Authenticator in Curity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Configuration using the Admin GUI
"""""""""""""""""""""""""""""""""

To configure a new WebAuthn authenticator using the Curity admin UI, do the following after logging in:

1. Go to the ``Authenticators`` page of the authentication profile wherein the authenticator instance should be created.
2. Click the ``New Authenticator`` button.
3. Enter a name (e.g., ``web-authn1``).
4. For the type, pick the ``WebAuthn`` option.
5. On the next page, you can define all of the standard authenticator configuration options like any previous authenticator that should run, the resulting ACR, transformers that should be executed, etc. At the bottom of the configuration page, the WebAuthn-specific options can be found.
6. Certain required configuration settings should be provided. One of these required settings is the ``AccountManager`` setting. This is the account manager that will be used to provide the accounts linked to the devices that are going to be used by the authenticator.
7. Select the ``Bucket`` to use, which sets the data-source for the authenticator.
8. Select the ``Algorithms`` that WebAuthn is going to choose one from for signing. The algorithms are selected in descending order of preference. Currently only ``ES256`` is supported by the WebAuthn compliant clients.
9. Finally, configure an ``Organisation Name`` that is going to be linked with the devices upon registration by WebAuthn.

Once all of these changes are made, they will be staged, but not committed (i.e., not running). To make them active, click the ``Commit`` menu option in the ``Changes`` menu. Optionally enter a comment in the ``Deploy Changes`` dialogue and click ``OK``.

Once the configuration is committed and running, the authenticator can be used like any other.

More Information
~~~~~~~~~~~~~~~~

Please visit `curity.io`_ for more information about the Curity Identity Server.

.. _curity.io/plugins: https://support.curity.io/docs/latest/developer-guide/plugins/index.html#plugin-installation
.. _curity.io: https://curity.io/
