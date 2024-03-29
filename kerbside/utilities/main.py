import click
import logging
import os
from PIL import Image
import re
from shakenfist_utilities import logs
import sys

from . import glz
from . import lz


LOG = logs.setup_console(__name__)


@click.group()
@click.pass_context
@click.option('--verbose/--no-verbose', default=False)
def cli(ctx, verbose):
    if not ctx.obj:
        ctx.obj = {}
    ctx.obj['VERBOSE'] = verbose

    if verbose:
        LOG.setLevel(logging.DEBUG)
        LOG.debug('Set log level to DEBUG')
    else:
        LOG.setLevel(logging.INFO)

    ctx.obj['LOGGER'] = LOG


@click.group('lz', help='LZ compression commands')
def lz_group():
    pass


cli.add_command(lz_group)


@lz_group.command(name='decompress', help='Decompress a raw LZ compressed frame')
@click.pass_context
@click.argument('source', type=click.Path(exists=True))
@click.argument('destination', type=click.Path(exists=False))
def lz_decompress(ctx, source, destination):
    with open(source, 'rb') as source_file:
        image_data = source_file.read()
        width, height, decompressed = lz.Decompress()(ctx, image_data)

    i = Image.frombuffer('RGBA', (width, height), decompressed,
                         'raw', 'RGBA', 0, 1)
    i.save(destination)


lz_group.add_command(lz_decompress)


@click.group('glz', help='GLZ compression commands')
def glz_group():
    pass


cli.add_command(glz_group)


GLZ_FILENAME_RE = re.compile('display-server-frame-([0-9]+).glz_rgb')


@glz_group.command(name='decompress', help='Decompress a raw GLZ compressed frame')
@click.pass_context
@click.argument('source', type=click.Path(exists=True))
@click.argument('destination', type=click.Path(exists=False))
@click.option('--global-dictionary/--no-global-dictionary', default=True)
def glz_decompress(ctx, source, destination, global_dictionary):
    previous_images = {}
    previous_images_ordered = []

    # If we have a global dictionary, assume the last portion of the filename
    # before the extension is a sequence number.
    if global_dictionary:
        m = GLZ_FILENAME_RE.match(source)
        if not m:
            print('Filename does not match pattern!')
            sys.exit(1)

        seq = int(m.group(1))

        for i in range(0, seq):
            img_path = 'display-server-frame-%08d.glz_rgb' % i
            ctx.obj['LOGGER'].info('Considering %s' % img_path)
            if os.path.exists(img_path):
                with open(img_path, 'rb') as source_file:
                    image_data = source_file.read()
                width, height, decompressed, img_id = glz.Decompress()(
                    ctx, image_data, previous_images)

                # Store the image, and make sure we know its new
                previous_images[img_id] = decompressed
                if img_id in previous_images_ordered:
                    previous_images_ordered.remove(img_id)
                previous_images_ordered.append(img_id)
                ctx.obj['LOGGER'].info('Loaded image id %d from %s'
                                       % (img_id, img_path))

                # Remove N images until we only have 16
                if len(previous_images_ordered) > 16:
                    for img_id in previous_images_ordered[:len(previous_images_ordered) - 16]:
                        previous_images_ordered.remove(img_id)

                i = Image.frombuffer('RGBA', (width, height), decompressed,
                                     'raw', 'RGBA', 0, 1)
                i.save(img_path.replace('.glz_rgb', '.png'))

    with open(source, 'rb') as source_file:
        image_data = source_file.read()
        width, height, decompressed, img_id = glz.Decompress()(
            ctx, image_data, previous_images)

    i = Image.frombuffer('RGBA', (width, height), decompressed,
                         'raw', 'RGBA', 0, 1)
    i.save(destination)


glz_group.add_command(glz_decompress)
