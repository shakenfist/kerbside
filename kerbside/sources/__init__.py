def driver_class(source_type):
    """Return the driver class for a source type.

    Raises KeyError for types which have no driver, such as openstack (which
    uses auth tokens rather than console discovery) and unknown types. The
    drivers are imported here, and looked up at call time, so that importing
    this package does not import every driver and its dependencies.
    """
    if source_type == 'shakenfist':
        from . import shakenfist
        return shakenfist.ShakenFistSource
    if source_type == 'ovirt':
        from . import ovirt
        return ovirt.oVirtSource
    if source_type == 'static':
        from . import static
        return static.StaticSource
    raise KeyError(source_type)
