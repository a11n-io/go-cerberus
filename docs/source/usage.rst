Usage
=====

.. _import:

Import
------------

To use go-cerberus, import it in your go project:

.. code-block:: console

    import (
        cerberus "github.com/a11n-io/go-cerberus"
    )

Creating the client
-------------------

To create the client you will use the ``cerberus.NewClient(baseUrl, apiKey, apiSecret string)`` function:

.. code-block:: console

cerberusClient := cerberus.NewClient("https://api_cerberus.a11n.io:80", "YOUR_CERBERUS_API_KEY", "YOUR_CERBERUS_API_SECRET")

The ``baseUrl`` parameter could be the hosted cloud, or your own installation url.
The ``apiKey`` and ``apiSecret`` parameters are generated on the cerberus dashboard for the app you're developing against.
